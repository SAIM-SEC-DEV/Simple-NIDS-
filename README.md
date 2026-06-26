# Network Intrusion Detection System (NIDS)

## Overview

This project is a C++ based educational Network Intrusion Detection System (NIDS) simulator designed to demonstrate fundamental intrusion detection concepts.

The system analyzes manually entered network packet information and detects suspicious activities such as SQL Injection attempts and potential port scanning behavior.

---

## Features

- SQL Injection Detection
- Port Scan Detection
- Threat Logging
- Packet Statistics Tracking
- CSV Alert Export
- Persistent Statistics Storage
- Console-Based User Interface

---

## Technologies Used

- C++
- File Handling
- Data Structures
- String Processing
- Console Application Development

---

## Detection Capabilities

### SQL Injection Detection

The system identifies common attack signatures including:

- `' OR '1'='1`
- `UNION SELECT`
- `DROP TABLE`
- `DELETE`
- Other suspicious SQL patterns

### Port Scan Detection

The system monitors traffic targeting commonly attacked ports:

- 21 (FTP)
- 22 (SSH)
- 23 (Telnet)
- 80 (HTTP)
- 443 (HTTPS)
- 3389 (RDP)
- 3306 (MySQL)
- 5432 (PostgreSQL)

---

## Project Structure

```text
src/
├── nidsupdate.cpp

screenshots/

README.md
.gitignore
```

---

## How to Compile

Using g++:

```bash
g++ nidsupdate.cpp -o nids
```

Run:

```bash
./nids
```

Windows:

```bash
nids.exe
```

---


## Learning Objectives

This project was developed to understand:

- Intrusion Detection Systems
- Network Security Concepts
- Threat Analysis
- File Handling in C++
- Security Event Logging

---

## Future Improvements

- Real Packet Capture Support
- Advanced Signature Detection
- GUI Dashboard
- Machine Learning Based Detection
- Real-Time Network Monitoring

---

## Author

Muhammad Saim Iftikhar

LinkedIn:
www.linkedin.com/in/saim-iftikhar-85aa90378

---

## License

This project is intended for educational and academic purposes.
