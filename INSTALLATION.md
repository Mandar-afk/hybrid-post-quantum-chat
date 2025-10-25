# Installation & Setup Notes

This file explains how to properly set up the **Hybrid Post-Quantum Chat Demo**, including common issues and their solutions.

---

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/Mandar-afk/hybrid-post-quantum-chat.git
cd hybrid-post-quantum-chat
```
## 2️⃣ Create & Activate a Virtual Environment (Recommended)
Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

Windows (PowerShell)
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Windows (CMD)
```
python -m venv venv
.\venv\Scripts\activate.bat
```


## 3️⃣ Install Dependencies
```
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

requirements.txt should contain at least:
```
cryptography
liboqs-python
```

## 4️⃣ Common Installation Issues
Issue 1: ModuleNotFoundError: No module named 'cryptography'

Cause: Virtual environment not activated or packages not installed.
Solution: Activate venv and run:
```
pip install -r requirements.txt
```

Issue 2: No OQS shared libraries found

Cause: liboqs-python needs C libraries that were not built or found.

Fix Steps:
Linux (Ubuntu/Debian)
```
sudo apt update
sudo apt install build-essential cmake libssl-dev python3-dev
```

macOS
```
brew install cmake openssl
```

Windows

Install Visual Studio Build Tools (C++ workload)

Install CMake and ensure it's in PATH

Reinstall liboqs-python
```
pip uninstall liboqs-python -y
pip install liboqs-python
```
Test the installation
```
import oqs
print(oqs.get_enabled_kem_mechanisms())
```

Should display a list like ['Kyber512', 'Kyber768', 'Kyber1024'].

Optional: Manual build (RECOMMENDED)
```
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build
pip install liboqs-python
```

## 5️⃣ Running the Demo

Start the server (User B):

python server.py


Start the client (User A) in another terminal:

python client.py


Ensure the server is running before starting the client.

## 6️⃣ Notes & Tips

Always use a fresh virtual environment for the project.

Do not push your venv folder; it is listed in .gitignore.

If using GitHub Codespaces or Docker, ensure required build tools are installed.

The project is for demo/learning purposes; production deployment requires additional security measures.


---

✅ **Features of this file:**
- Step-by-step setup instructions  
- venv creation and activation for all platforms  
- Fixes for common Python module and `liboqs` issues  
- Clear instructions for running the server/client  
- Notes for future users  

---
