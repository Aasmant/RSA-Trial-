# RSA-Based File Encryption Service - Secure SDLC Case Study


## Overview

This repository demonstrates a comprehensive implementation of Secure Software Development Lifecycle (SSDLC) principles through an RSA-based file encryption service. The project serves as showcasing security requirements engineering, threat modeling, secure architecture design, and comprehensive security testing throughout all phases of the development lifecycle.

The implementation features RSA asymmetric encryption, JWT-based authentication, RESTful API design, and includes intentional security vulnerabilities with corresponding detection tests to demonstrate effective security testing methodologies.

---

### Technology Stack
- **Backend Framework**: Java 17 + Spring Boot 3.x
- **Database**: SQLite with JPA/Hibernate
- **Authentication**: JWT (JSON Web Tokens)
- **Encryption**: RSA-2048 (asymmetric) + AES-256 (symmetric)
- **Testing**: JUnit 5 (Jupiter)
- **Build Tool**: Maven 3.9+
- **CI/CD**: GitHub Actions

---

## Prerequisites

- **Java**: 17 or higher
- **Maven**: 3.9 or higher
- **SQLite**: Embedded (no separate installation required)

---

## 🚀 Quick Start Guide

### Step 1: Download the Repository

```bash
git clone https://github.com/Aasmant/RSA-Trial-.git
cd RSA-Trial-/RSA-JavaSpringboot
```

---

### Step 2: Start the Server (Terminal 1)

```bash
mvn spring-boot:run
```

✅ **Server running at:** `http://localhost:5000`

---

### Step 3: Run the Client (Terminal 2)

Open a **new terminal** in the same directory:

```bash
python3 client.py
```

✅ **Client ready!** You can now interact with the encryption service.

---

## 🧪 Running Tests (Optional)

If you want to explore the security testing features:

```bash
# Run all tests (12 total: 4 pass, 8 intentional failures)
mvn test

# Run only secure implementation tests (4 pass)
mvn test -Dtest=SecureImplementationTest

# Run only vulnerability detection tests (8 intentional failures)
mvn test -Dtest=VulnerabilityDemonstrationTest
```

---

## 📋 Summary

| Step | Terminal | Command | Purpose |
|------|----------|---------|---------|
| 1 | Terminal 1 | `mvn spring-boot:run` | Start backend server |
| 2 | Terminal 2 | `python3 client.py` | Start client interface |

---

