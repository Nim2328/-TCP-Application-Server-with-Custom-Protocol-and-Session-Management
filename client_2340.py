import socket
import sys

HOST = '127.0.0.1'
PORT = 50340
SID = '1023'

def send_protocol(sock, message):
    payload = message.encode('utf-8')
    length_header = f"LEN:{len(payload)}\n".encode('utf-8')
    sock.sendall(length_header + payload)

def recv_response(sock):
    data = b""
    while True:
        part = sock.recv(1024)
        if not part:
            break
        data += part
        if b'\n' in part:
            break
    return data.decode('utf-8').strip()

def main():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        print(f"Connected to Server (SID: {SID})")
        
        while True:
            print("\n1. REGISTER  2. LOGIN  3. LOGOUT  4. UPLOAD  5. EXIT")
            choice = input("Choose: ")
            
            if choice == '1':
                user = input("Username: ")
                pwd = input("Password: ")
                send_protocol(sock, f"REGISTER {user} {pwd}")
            elif choice == '2':
                user = input("Username: ")
                pwd = input("Password: ")
                send_protocol(sock, f"LOGIN {user} {pwd}")
            elif choice == '3':
                send_protocol(sock, "LOGOUT")
            elif choice == '4':
                send_protocol(sock, "UPLOAD myfile.txt")
            elif choice == '5':
                break
            
            print(recv_response(sock))
                
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    Main()