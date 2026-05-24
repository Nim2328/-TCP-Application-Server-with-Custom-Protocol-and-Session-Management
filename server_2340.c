#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* ==================== CONFIGURATION FOR IT24102340 ==================== */
#define PORT 50340
#define SID "1023"
#define LOG_FILE "server_IT24102340.log"
#define USER_DB "/srv/ie2102/IT24102340/users.dat"
#define SESSION_DB "/srv/ie2102/IT24102340/sessions.dat"
#define MAX_PAYLOAD 4096
#define TOKEN_EXPIRY 300
#define MAX_FAILED_ATTEMPTS 5
#define USERNAME_MAX 32

/* ==================== STRUCTURES ==================== */
typedef struct {
    char username[50];
    char salt[16];
    char hash[65];
} UserRecord;

typedef struct {
    char username[50];
    char token[65];
    time_t last_activity;
    char client_ip[50];
} SessionRecord;

typedef struct {
    char client_ip[50];
    int failed_count;
    time_t lockout_until;
} FailedAttempt;

static FailedAttempt failed_attempts[100];
static int failed_count = 0;

/* ==================== HELPER FUNCTIONS ==================== */

void write_log(const char *client_ip, int pid, const char *user, const char *cmd, const char *result) {
    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp)-1] = 0;
    
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "[%s] [PID:%d] [Client:%s] [User:%s] [CMD:%s] [RES:%s]\n", 
                timestamp, pid, client_ip, user, cmd, result);
        fclose(f);
    }
}

void get_client_ip(int sock, char *ip_buffer) {
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(addr);
    getpeername(sock, (struct sockaddr*)&addr, &addr_size);
    sprintf(ip_buffer, "%s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
}

void generate_salt(char *salt) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < 15; i++) {
        salt[i] = chars[rand() % strlen(chars)];
    }
    salt[15] = 0;
}

/* ==================== SHA256 HASHING (OpenSSL) ==================== */
void sha256_hash(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = 0;
}

/* ==================== RATE LIMITING & LOCKOUT ==================== */

int check_lockout(const char *client_ip) {
    time_t now = time(NULL);
    for (int i = 0; i < failed_count; i++) {
        if (strcmp(failed_attempts[i].client_ip, client_ip) == 0) {
            if (now < failed_attempts[i].lockout_until) {
                return 1;
            } else {
                failed_attempts[i].failed_count = 0;
                failed_attempts[i].lockout_until = 0;
            }
        }
    }
    return 0;
}

void record_failed_attempt(const char *client_ip) {
    time_t now = time(NULL);
    for (int i = 0; i < failed_count; i++) {
        if (strcmp(failed_attempts[i].client_ip, client_ip) == 0) {
            failed_attempts[i].failed_count++;
            if (failed_attempts[i].failed_count >= MAX_FAILED_ATTEMPTS) {
                failed_attempts[i].lockout_until = now + 300;
            }
            return;
        }
    }
    if (failed_count < 100) {
        strcpy(failed_attempts[failed_count].client_ip, client_ip);
        failed_attempts[failed_count].failed_count = 1;
        failed_attempts[failed_count].lockout_until = 0;
        failed_count++;
    }
}

void reset_failed_attempts(const char *client_ip) {
    for (int i = 0; i < failed_count; i++) {
        if (strcmp(failed_attempts[i].client_ip, client_ip) == 0) {
            failed_attempts[i].failed_count = 0;
            failed_attempts[i].lockout_until = 0;
            return;
        }
    }
}

/* ==================== PROTOCOL HANDLING (A1) ==================== */

int read_exact(int sock, char *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = recv(sock, buf + total, len - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return 0;
}

int parse_protocol(int sock, char *buffer, int *len_out) {
    char len_buf[20] = {0};
    int i = 0;
    char c;
    
    while (i < 19) {
        if (recv(sock, &c, 1, 0) <= 0) return -1;
        len_buf[i++] = c;
        if (c == '\n') break;
    }
    len_buf[i] = 0;
    
    if (strncmp(len_buf, "LEN:", 4) != 0) return -1;
    int payload_len = atoi(len_buf + 4);
    
    if (payload_len > MAX_PAYLOAD) {
        send(sock, "ERR500 SID:1023 Payload Too Large\n", 33, 0);
        return -1;
    }
    
    if (read_exact(sock, buffer, payload_len) < 0) return -1;
    buffer[payload_len] = 0;
    *len_out = payload_len;
    return 0;
}

/* ==================== AUTH & SESSION LOGIC (A3) ==================== */

int register_user(const char *username, const char *password) {
    FILE *f = fopen(USER_DB, "r");
    if (f) {
        UserRecord rec;
        while (fread(&rec, sizeof(UserRecord), 1, f)) {
            if (strcmp(rec.username, username) == 0) {
                fclose(f);
                return 0;
            }
        }
        fclose(f);
    }
    
    f = fopen(USER_DB, "a");
    if (!f) return -1;
    
    UserRecord rec;
    memset(&rec, 0, sizeof(UserRecord));
    strcpy(rec.username, username);
    generate_salt(rec.salt);
    
    char combined[100];
    sprintf(combined, "%s%s", password, rec.salt);
    sha256_hash(combined, rec.hash);
    
    fwrite(&rec, sizeof(UserRecord), 1, f);
    fclose(f);
    return 1;
}

int login_user(const char *username, const char *password, char *token_out) {
    FILE *f = fopen(USER_DB, "r");
    if (!f) return 0;
    
    UserRecord rec;
    int found = 0;
    
    while (fread(&rec, sizeof(UserRecord), 1, f)) {
        if (strcmp(rec.username, username) == 0) {
            char combined[100];
            sprintf(combined, "%s%s", password, rec.salt);
            
            char input_hash[65];
            sha256_hash(combined, input_hash);
            
            if (strcmp(input_hash, rec.hash) == 0) {
                found = 1;
                sprintf(token_out, "%s_%ld", username, (long)time(NULL));
            }
            break;
        }
    }
    
    fclose(f);
    return found;
}

void create_session(const char *username, const char *token, const char *ip) {
    FILE *f = fopen(SESSION_DB, "a");
    if (!f) return;
    
    SessionRecord rec;
    memset(&rec, 0, sizeof(SessionRecord));
    strcpy(rec.username, username);
    strcpy(rec.token, token);
    strcpy(rec.client_ip, ip);
    rec.last_activity = time(NULL);
    
    fwrite(&rec, sizeof(SessionRecord), 1, f);
    fclose(f);
}

/* ==================== CLIENT HANDLER ==================== */

void handle_client(int sock) {
    char buffer[MAX_PAYLOAD];
    char client_ip[50];
    char current_user[50] = "UNKNOWN";
    int payload_len;
    pid_t pid = getpid();
    
    get_client_ip(sock, client_ip);
    write_log(client_ip, pid, "-", "CONNECT", "SUCCESS");

    while (1) {
        if (parse_protocol(sock, buffer, &payload_len) < 0) break;

        char cmd[20] = {0}, arg1[50] = {0}, arg2[50] = {0}, token[65] = {0};
        sscanf(buffer, "%s %s %s %s", cmd, arg1, arg2, token);
        
        char response[256] = {0};
        int authenticated = 0;

        if (check_lockout(client_ip)) {
            sprintf(response, "ERR429 SID:%s Too Many Attempts\n", SID);
            send(sock, response, strlen(response), 0);
            write_log(client_ip, pid, current_user, cmd, "LOCKOUT");
            continue;
        }

        if (strcmp(cmd, "LOGIN") != 0 && strcmp(cmd, "REGISTER") != 0 && strcmp(cmd, "LOGOUT") != 0) {
            if (strcmp(current_user, "UNKNOWN") == 0) {
                sprintf(response, "ERR401 SID:%s Authentication Required\n", SID);
                send(sock, response, strlen(response), 0);
                write_log(client_ip, pid, current_user, cmd, "FAIL_AUTH");
                continue;
            }
            authenticated = 1;
        }

        if (strcmp(cmd, "REGISTER") == 0) {
            if (strlen(arg1) < 3 || strlen(arg2) < 6) {
                sprintf(response, "ERR400 SID:%s Invalid Format\n", SID);
            } else {
                int res = register_user(arg1, arg2);
                if (res == 1) {
                    sprintf(response, "OK200 SID:%s Registration Successful\n", SID);
                } else if (res == 0) {
                    sprintf(response, "ERR409 SID:%s User Exists\n", SID);
                } else {
                    sprintf(response, "ERR500 SID:%s Server Error\n", SID);
                }
            }
            write_log(client_ip, pid, arg1, "REGISTER", (strstr(response, "OK") ? "SUCCESS" : "FAIL"));
        }
        else if (strcmp(cmd, "LOGIN") == 0) {
            if (strlen(arg1) < 3 || strlen(arg2) < 6) {
                sprintf(response, "ERR400 SID:%s Invalid Format\n", SID);
            } else {
                char token_gen[65];
                if (login_user(arg1, arg2, token_gen)) {
                    strcpy(current_user, arg1);
                    create_session(arg1, token_gen, client_ip);
                    sprintf(response, "OK200 SID:%s Login Success Token:%s\n", SID, token_gen);
                    write_log(client_ip, pid, arg1, "LOGIN", "SUCCESS");
                    reset_failed_attempts(client_ip);
                } else {
                    sprintf(response, "ERR401 SID:%s Invalid Credentials\n", SID);
                    write_log(client_ip, pid, arg1, "LOGIN", "FAIL");
                    record_failed_attempt(client_ip);
                }
            }
        }
        else if (strcmp(cmd, "LOGOUT") == 0) {
            strcpy(current_user, "UNKNOWN");
            sprintf(response, "OK200 SID:%s Logged Out\n", SID);
            write_log(client_ip, pid, "-", "LOGOUT", "SUCCESS");
        }
        else if (strcmp(cmd, "UPLOAD") == 0 && authenticated) {
            sprintf(response, "OK200 SID:%s File Uploaded\n", SID);
            write_log(client_ip, pid, current_user, "UPLOAD", "SUCCESS");
        }
        else {
            sprintf(response, "ERR400 SID:%s Unknown Command\n", SID);
            write_log(client_ip, pid, current_user, cmd, "FAIL_CMD");
        }

        send(sock, response, strlen(response), 0);
    }
    
    close(sock);
    write_log(client_ip, pid, current_user, "DISCONNECT", "SUCCESS");
    exit(0);
}

/* ==================== SIGNAL HANDLER (A2) ==================== */

void sigchld_handler(int s) {
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

/* ==================== MAIN ==================== */

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    srand(time(NULL));

    struct sigaction sa;
    sa.sa_handler = &sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server Running on Port %d (SID: %s)\n", PORT, SID);

    for (;;) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        if (fork() == 0) {
            close(server_fd);
            handle_client(new_socket);
        }
        close(new_socket);
    }
    return 0;
}