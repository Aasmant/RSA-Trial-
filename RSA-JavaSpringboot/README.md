# RSA Encryption Service - Java Spring Boot Implementation

Java Spring Boot implementation of the RSA-based file encryption service demonstrating Secure Software Development Lifecycle (SSDLC) principles.

**For complete project information, see the [main README](../README.md).**

---

## What's Included

This implementation contains:

- **REST API**: File encryption/decryption endpoints with JWT authentication
- **Cryptographic Services**: RSA asymmetric and AES symmetric encryption  
- **Database Layer**: SQLite with JPA/Hibernate for user and file management
- **Audit Logging**: Security event tracking
- **Security Tests**: Comprehensive test suites demonstrating vulnerability detection and secure implementations

---

## Project Structure

```
RSA-JavaSpringboot/
├── src/
│   ├── main/java/com/example/rsa/
│   │   ├── controller/          # REST API endpoints (ApiController)
│   │   ├── service/             # Business logic (EncryptionService, AuditService)
│   │   ├── model/               # JPA entities (User, FileEntity, AuditLog)
│   │   ├── repository/          # Data access layer
│   │   └── util/                # Utilities (JwtUtil)
│   └── test/java/com/example/rsa/
│       └── security/            # Security test suites
│           ├── VulnerabilityDemonstrationTest.java
│           └── SecureImplementationTest.java
├── pom.xml                      # Maven dependencies and configuration
├── client.py                    # Python CLI client for testing
└── README.md                    # This file
```

---

## Prerequisites

- **Java**: 17 or higher
- **Maven**: 3.9 or higher

---

## How to Run

### Build the Project
```bash
mvn clean install
```

### Run the Application
```bash
mvn spring-boot:run
```

The server will start on **port 5000** (configured in `application.properties`).

Server URL: `http://localhost:5000`

### Use the Python Client (Optional)
```bash
python3 client.py
```

---

## Running Tests

### All Tests
```bash
mvn test
```

### Security Tests Only
```bash
mvn test -Dtest="*security*"
```

### Vulnerability Detection Tests
```bash
mvn test -Dtest=VulnerabilityDemonstrationTest
```
**Note**: These tests intentionally fail to demonstrate vulnerability detection (8 expected failures).

### Secure Implementation Tests
```bash
mvn test -Dtest=SecureImplementationTest
```
**Note**: These tests validate correct security practices (4 expected passes).

---

## Test Suites Overview

### VulnerabilityDemonstrationTest.java
8 tests that intentionally fail, each detecting a specific security vulnerability:
- Cryptographic weaknesses (textbook RSA, weak key sizes)
- Secret management issues (hardcoded JWT secret)
- Authorization flaws (IDOR)
- Information leakage (private keys, verbose errors)
- Hash weaknesses (MD5 usage)
- Missing security controls (no rate limiting)

### SecureImplementationTest.java  
4 tests that pass, validating secure implementations:
- OAEP padding for probabilistic encryption
- Strong 2048-bit RSA keys
- Private keys not exposed in API responses
- Complete secure encryption/decryption flow

---

## API Endpoints

For complete API documentation, see the [main README](../README.md#api-documentation).

Quick reference:
- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `POST /api/upload` - Upload encrypted file
- `GET /api/files` - List user's files
- `GET /api/download/{fileId}` - Download file
- `POST /api/decrypt/{fileId}` - Decrypt file
- `GET /api/health` - Health check

---

## Educational Purpose

⚠️ **This implementation contains intentional security vulnerabilities for educational purposes.**

The vulnerabilities are:
- Clearly documented in test files and documentation
- Detected by automated test suites  
- Include remediation guidance
- Demonstrate effective security testing methodologies

**DO NOT USE IN PRODUCTION**

---

## Documentation

For comprehensive documentation, see:
- **[Main README](../README.md)** - Complete project overview and all 8 SSDLC questions
- **[QUESTION_6_THEORY_FOR_REPORT.md](../QUESTION_6_THEORY_FOR_REPORT.md)** - Security testing theory for report writing
- **[SECURITY_TEST_RESULTS.md](../SECURITY_TEST_RESULTS.md)** - Detailed test results and findings
- **[SECURITY_TESTING_STRATEGY.md](../SECURITY_TESTING_STRATEGY.md)** - Testing strategy and compliance

---

## Technology Stack

- **Framework**: Spring Boot 3.x
- **Language**: Java 17
- **Database**: SQLite (embedded)
- **ORM**: JPA/Hibernate
- **Authentication**: JWT (JSON Web Tokens)
- **Encryption**: Java Cipher API (RSA + AES)
- **Testing**: JUnit 5 (Jupiter)
- **Build**: Maven

---

## Support

For questions or issues:
1. Check the [main README](../README.md) for complete documentation
2. Review test files for implementation examples
3. Consult security documentation files for detailed analysis
