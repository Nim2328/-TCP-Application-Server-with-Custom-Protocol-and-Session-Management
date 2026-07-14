# -TCP-Application-Server-with-Custom-Protocol-and-Session-Management
# Secure Multiprocessor TCP Application Server

A secure TCP-based client-server application developed as part of the **IE2102 – Network Programming** module at **Sri Lanka Institute of Information Technology (SLIIT)**.

This project demonstrates secure network programming concepts including multiprocessing, custom protocol design, session management, secure authentication, abuse protection, and audit logging using the C programming language and Python.

---

# Project Overview

This application implements a secure multi-client TCP server capable of handling multiple client connections simultaneously using process-based concurrency.

The server is developed in **C** using the POSIX Socket API while the client application is developed in **Python 3**.

The system was designed according to the assignment requirements and focuses on secure communication, authentication, scalability and reliability.

---

# Features

## Network Programming

- TCP Socket Programming
- Client-Server Architecture
- Custom Application Layer Protocol
- Reliable TCP Communication
- Dynamic Payload Handling
- Variable Length Message Framing

---

## Multiprocessing

- Multi-client support
- One child process per client
- Process creation using `fork()`
- Parent process continues accepting new connections
- Proper child cleanup using `SIGCHLD`
- Zombie process prevention using `waitpid()`

---

## Authentication

- User Registration
- User Login
- User Logout
- Session Token Generation
- Session Token Validation
- Session Expiration after inactivity

---

## Security Features

- Salted SHA-256 Password Hashing
- Plain-text password prevention
- Username validation
- Payload overflow protection
- Brute-force attack protection
- Login attempt limitation
- IP-based lockout
- Secure session management

---

## Custom Protocol

Every client request follows the custom protocol:

```

LEN:<payload\_length>

<payload>

```

Example

```

LEN:24
LOGIN user1 password

```

The protocol ensures:

- Correct message boundaries
- Partial packet handling
- Buffer overflow prevention
- Reliable communication

---

# Supported Commands

| Command | Description |
|----------|-------------|
| REGISTER username password | Create new account |
| LOGIN username password | Authenticate user |
| LOGOUT | Logout current session |
| UPLOAD filename | Upload a file (Requires Login) |

---

# Project Architecture

```

+----------------+
| Python Client |
+----------------+
|
| TCP
|
+-----------------------------+
| Secure TCP Server (C) |
+-----------------------------+
|
+-------------------------+
| Authentication Module |
+-------------------------+
|
+-------------------------+
| Session Manager |
+-------------------------+
|
+-------------------------+
| Audit Logger |
+-------------------------+
|
+-------------------------+
| User Database |
+-------------------------+

```

---

# Security Implementation

## Password Storage

- Random Salt Generation
- SHA-256 Hashing
- Password + Salt Combination
- Plain-text passwords are never stored

---

## Session Management

- Unique Session Tokens
- Token Validation
- Automatic Timeout
- Logout Support

---

## Abuse Protection

- Maximum payload size validation
- Username sanitization
- Brute-force login protection
- Failed login tracking
- Temporary IP lockout

---

## Audit Logging

Every transaction is recorded including:

- Timestamp
- Client IP Address
- Port Number
- Child Process ID
- Username
- Command Executed
- Operation Result

---

# Technologies Used

## Programming Languages

- C
- Python 3

## Networking

- TCP/IP
- POSIX Socket API

## Security

- SHA-256
- Salted Password Hashing
- Session Tokens

## Operating System

- Ubuntu Linux
- VMware

## Build Tool

- Makefile

---

# Folder Structure

```

project/
│
├── server.c
├── client.py
├── sha256.c
├── sha256.h
├── Makefile
│
├── users.dat
├── sessions.dat
│
├── uploads/
│
├── server\_IT24102340.log
│
├── README.md

```

---

# Build Instructions

Compile the project

```bash
make
```

Run the server

```bash
./server
```

Run the client

```bash
python3 client.py
```

---

# Testing

The following functionality has been successfully tested.

- Server Startup
- Port Listening
- User Registration
- Successful Login
- Failed Login
- Brute-force Lockout
- Session Token Generation
- Session Validation
- File Upload
- Concurrent Client Connections
- Child Process Cleanup
- Audit Logging

---

# Screenshots

The project includes screenshots demonstrating

- Server Execution
- Client Execution
- Registration
- Login
- Failed Login
- Session Token
- Multiprocessing
- Process Management
- Audit Logs
- Network Configuration
- Port Listening

---

# Learning Outcomes

Through this project, the following concepts were implemented and demonstrated.

- TCP Socket Programming
- Client-Server Architecture
- Process Management
- Multiprocessing
- Custom Network Protocol Design
- Secure Authentication
- Session Management
- Linux System Programming
- Secure Password Storage
- Network Security
- Audit Logging
- Error Handling

---

# Future Improvements

- TLS/SSL Encryption
- SQLite/MySQL Integration
- IPv6 Support
- Role-Based Authentication
- File Download Support
- Multi-threaded Server Version
- GUI Client Application
- REST API Integration

---

# Author

**K. M. Nirmal Shehan Nayanajith**

B.Sc. (Hons) in Information Technology

Specialization: Cyber Security

Sri Lanka Institute of Information Technology (SLIIT)

Student ID: **IT24102340**

---

# Module Information

**Module:** IE2102 – Network Programming

**Faculty:** Faculty of Computing

**University:** Sri Lanka Institute of Information Technology (SLIIT)

---

# License

This project was developed for academic and educational purposes as part of the IE2102 Network Programming module.

Copyright © 2026 K. M. Nirmal Shehan Nayanajith
