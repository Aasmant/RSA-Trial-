# RSA Encryption Service - Setup & Run Instructions

## Project Overview

This is a Software Security SSDLC assignment demonstrating a secure RSA-based file encryption service.

**GitHub Repository:** https://github.com/Aasmant/RSA

---

## 🚀 Quick Start Guide

### Step 1: Installation
Prerequisites: Python 3.9+

```bash
# 1. Clone repository (if you haven't)
# git clone https://github.com/Aasmant/RSA.git
# cd RSA

# 2. Install dependencies
pip3 install -r requirements.txt
```

### Step 2: Run the Service
Open Terminal 1 and start the server:

```bash
python3 rsa_service.py
```
_You should see "Running on http://127.0.0.1:5000"_

### Step 3: Run the CLI Client (Recommended)
Open Terminal 2 and use the interactive client:

```bash
python3 client.py
```

The CLI provides a menu to easily perform all actions:
1. **Register** a new user
2. **Login**
3. **Upload** files (Encrypted automatically)
4. **List** files
5. **Download & Decrypt** files

---

## 🔧 Manual API Testing (Alternative)

If you prefer using `curl` directly without the client script:

**1. Check Health**
```bash
curl http://localhost:5000/api/health
```

**2. Register**
```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

**3. Login**
```bash
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```
_Copy the `token` from the response for the next steps._

**4. Upload File**
```bash
# Replace YOUR_TOKEN
curl -X POST http://localhost:5000/api/upload \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@test.txt"
```

---

## 🧹 Reset/Cleanup

To reset the database and delete all users/files:

```bash
# Stop the server (Ctrl+C)
rm rsa_service.db
# Restart the server to generate a clean database
```

---

## Project Files Reference

- `rsa_service.py` - Main REST API application
- `client.py` - Interactive CLI Client
- `requirements.txt` - Python dependencies
- `SECURITY_REPORT.md` - Comprehensive Security Analysis
- `THREAT_MODEL.md` - Threat modeling (STRIDE)
