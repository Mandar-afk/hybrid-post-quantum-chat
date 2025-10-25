# Hybrid Post-Quantum Chat Demo

## Overview
This project demonstrates a **hybrid post-quantum cryptography system** combining:

- **RSA** (classical asymmetric encryption)  
- **Kyber** (post-quantum key encapsulation mechanism)  
- **AES-GCM** (authenticated symmetric encryption)

It simulates a **two-user chat** over TCP sockets using a hybrid key exchange.

---

## Features
- Hybrid AES key derived from **classical RSA + Kyber KEM**  
- Encrypted message exchange using **AES-GCM**  
- Demonstrates **post-quantum readiness** and hybrid cryptography concepts  

---

## Requirements
- Python 3.10+  
- Packages listed in `requirements.txt`:

```text
cryptography
liboqs-python
```
## Installation
Check the Installation.md file.

## Usage

Run the server (User B):
```
python server.py
```

Run the client (User A):
```
python client.py
```

Use two dedicated terminals, one for the server and the other one for the client. Make sure you run the server file first and then the client one.

## Notes

Demo only: public keys are not authenticated, MITM attacks are possible.

Use unique AES-GCM nonces per message.

Designed to demonstrate hybrid cryptography concepts.
