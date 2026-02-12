# RSA-Based File Encryption Service - Secure SDLC Case Study

[![Security Tests](https://github.com/Aasmant/RSA-Trial-/actions/workflows/security-tests.yml/badge.svg)](https://github.com/Aasmant/RSA-Trial-/actions/workflows/security-tests.yml)

## Overview

This repository demonstrates a comprehensive implementation of Secure Software Development Lifecycle (SSDLC) principles through an RSA-based file encryption service. The project serves as an educational case study showcasing security requirements engineering, threat modeling, secure architecture design, and comprehensive security testing throughout all phases of the development lifecycle.

The implementation features RSA asymmetric encryption, JWT-based authentication, RESTful API design, and includes intentional security vulnerabilities with corresponding detection tests to demonstrate effective security testing methodologies.

---

## Project Scope

This project demonstrates comprehensive coverage of 8 key questions in Secure Software Development Lifecycle (SSDLC):

### Question 1: Security Requirements Engineering
Security requirements are identified and documented from project inception, including confidentiality (encryption at rest and in transit), authentication (JWT-based), authorization (user-based file access), and compliance considerations (NIST, OWASP standards).

**Documentation**: Security requirements integrated throughout codebase and testing strategy.

### Question 2: Threat Modeling and Risk Assessment
Comprehensive threat analysis identifying assets (private keys, user data, JWT tokens), threat actors (unauthorized users, attackers), and attack vectors (IDOR, key exposure, weak cryptography). Risk assessment categorizes vulnerabilities by severity (Critical, High, Medium, Low).

**Documentation**: Threat model reflected in test categories and security controls.

### Question 3: Secure Software Architecture & Design
System architecture implements defense-in-depth principles with layered security controls: authentication layer (JWT), encryption layer (RSA + AES), data access layer (authorization checks), and audit layer (logging). Design patterns follow OWASP secure coding guidelines.

**Documentation**: Architecture described in this README; secure design patterns demonstrated in SecureImplementationTest.

### Question 4: Authentication & Authorization
JWT-based authentication system with secure token generation and validation. Authorization implements resource-level access controls ensuring users can only access their own encrypted files. Tests validate both secure implementations and identify IDOR vulnerabilities.

**Documentation**: API endpoints section; authentication tests in security test suites.

### Question 5: Secure Implementation and Code Assurance
Implementation follows secure coding practices with proper use of cryptographic libraries (Java Cipher API), secure key management patterns, and input validation. Code demonstrates both secure and insecure patterns for educational comparison.

**Documentation**: Source code in `RSA-JavaSpringboot/src/main/java/`; comparative tests in test suites.

### Question 6: Security Testing, Validation, and Compliance
Comprehensive security testing strategy with 12 automated tests covering vulnerability detection and secure implementation verification. Testing addresses NIST, OWASP, PCI-DSS, and HIPAA compliance requirements. CI/CD pipeline provides continuous security validation.

**Documentation**: 
- **[QUESTION_6_THEORY_FOR_REPORT.md](QUESTION_6_THEORY_FOR_REPORT.md)** - Complete theoretical foundation for report writing
- **[SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md)** - Detailed test results and technical findings  
- **[SECURITY_TESTING_STRATEGY.md](SECURITY_TESTING_STRATEGY.md)** - Testing strategy and SSDLC integration
- Test implementations in `RSA-JavaSpringboot/src/test/java/com/example/rsa/security/`

### Question 7: Secure Deployment, Operations, and Incident Response
Deployment considerations include secure configuration management (environment variables for secrets), monitoring and logging (audit trails for security events), and incident response planning (vulnerability remediation roadmap).

**Documentation**: CI/CD workflow in `.github/workflows/security-tests.yml`; remediation roadmap in SECURITY_TEST_RESULTS.md.

### Question 8: Maintenance, Evolution, and Cryptographic Agility
Project demonstrates cryptographic agility through modular design allowing algorithm upgrades. Remediation roadmap shows evolution path from insecure implementations (textbook RSA, MD5) to secure alternatives (OAEP padding, bcrypt). Maintenance considerations include security regression testing.

**Documentation**: Migration guidance in SECURITY_TEST_RESULTS.md; secure alternatives demonstrated in tests.

---

## Architecture

### System Components

```
┌─────────────────┐
│   Client App    │
│  (Python CLI)   │
└────────┬────────┘
         │ HTTPS/JWT
         ▼
┌─────────────────────────────────┐
│    REST API Layer               │
│  (Spring Boot Controller)       │
│  - Authentication (JWT)         │
│  - Authorization checks         │
│  - Input validation             │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│    Business Logic Layer         │
│  - EncryptionService (RSA/AES)  │
│  - AuditService (logging)       │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│    Data Access Layer            │
│  - User Repository              │
│  - File Repository              │
│  - Audit Repository             │
└────────┬────────────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│    Database (SQLite)            │
│  - Users (credentials, keys)    │
│  - Files (encrypted data)       │
│  - Audit logs                   │
└─────────────────────────────────┘
```

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

## Installation and Running

### Java Spring Boot Implementation

```bash
# Clone repository
cd /path/to/RSA-Trial-

# Navigate to Java implementation
cd RSA-JavaSpringboot

# Build project
mvn clean install

# Run application
mvn spring-boot:run
```

**Server runs on**: `http://localhost:5000`

### Running Tests

```bash
# Run all tests
mvn test

# Run security tests only
mvn test -Dtest="*security*"

# Run vulnerability detection tests (8 intentional failures)
mvn test -Dtest=VulnerabilityDemonstrationTest

# Run secure implementation tests (4 expected passes)
mvn test -Dtest=SecureImplementationTest
```

---

## API Documentation

### Authentication Endpoints

**Register New User**
```
POST /api/register
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "SecurePass123!"
}

Response: JWT token + public key
```

**User Login**
```
POST /api/login
Content-Type: application/json

{
  "username": "user@example.com", 
  "password": "SecurePass123!"
}

Response: JWT token
```

### File Operations Endpoints

**Upload Encrypted File**
```
POST /api/upload
Authorization: Bearer {jwt_token}
Content-Type: multipart/form-data

file: [binary file data]

Response: File metadata with ID
```

**List User's Files**
```
GET /api/files
Authorization: Bearer {jwt_token}

Response: Array of file metadata
```

**Download Encrypted File**
```
GET /api/download/{fileId}
Authorization: Bearer {jwt_token}

Response: Encrypted file binary data
```

**Decrypt File**
```
POST /api/decrypt/{fileId}
Authorization: Bearer {jwt_token}
Content-Type: application/json

{
  "private_key": "-----BEGIN PRIVATE KEY-----\n..."
}

Response: Decrypted file binary data
```

### Health Check Endpoint

**Service Health**
```
GET /api/health

Response: { "status": "UP" }
```

---

## Documentation Structure

### For Report Writing (Question 6)
- **[QUESTION_6_THEORY_FOR_REPORT.md](QUESTION_6_THEORY_FOR_REPORT.md)** - Comprehensive theoretical content about security testing, validation, and compliance. Organized for direct incorporation into academic reports.

### Technical Documentation
- **[SECURITY_TEST_RESULTS.md](SECURITY_TEST_RESULTS.md)** - Detailed test execution results, vulnerability findings, remediation guidance, and technical analysis.
- **[SECURITY_TESTING_STRATEGY.md](SECURITY_TESTING_STRATEGY.md)** - Overall testing strategy, SSDLC phase integration, and compliance mapping.

### Implementation Documentation
- **[RSA-JavaSpringboot/README.md](RSA-JavaSpringboot/README.md)** - Java Spring Boot implementation specifics
- **Source Code**: `RSA-JavaSpringboot/src/main/java/` - Application implementation
- **Test Code**: `RSA-JavaSpringboot/src/test/java/` - Comprehensive test suites with documentation

---

## Security Testing Approach

This project demonstrates an educational approach to security testing where automated tests detect both vulnerabilities and validate secure implementations.

### Test Categories

**Vulnerability Detection Tests** (8 tests - intentionally fail to demonstrate detection)
- Located in: `VulnerabilityDemonstrationTest.java`
- Detect: Cryptographic weaknesses, hardcoded secrets, authorization flaws, information leakage
- Purpose: Prove that automated testing can identify real security vulnerabilities

**Secure Implementation Tests** (4 tests - pass to validate correct practices)
- Located in: `SecureImplementationTest.java`  
- Validate: Proper encryption (OAEP padding), strong key sizes (2048-bit), secure API design
- Purpose: Demonstrate correct implementations following security standards

### Key Educational Insight

The project demonstrates that **failing security tests can indicate success** - successful detection of vulnerabilities that need remediation. This is explicitly addressed in the professor's requirement: *"Even if your unit testing would find that your own RSA textbook implementation is weak (e.g. deterministic) that would be a great observation."*

The test `testTextbookRSAIsDeterministic()` intentionally fails, proving that unit testing successfully detects this cryptographic weakness.

---

## Educational Purpose

⚠️ **This project is for educational purposes only.**

This service intentionally includes certain security implementations designed to demonstrate security testing and validation techniques as part of an academic assignment on Secure Software Development Lifecycle (SSDLC).

### Important Disclaimers

**NOT FOR PRODUCTION USE**

This project contains intentional security vulnerabilities for educational demonstration:
- Vulnerabilities are clearly documented with severity ratings
- Each vulnerability has corresponding detection tests
- Remediation guidance is provided for learning purposes
- Both insecure and secure implementations are shown for comparison

### Intended Audience

- University students studying secure software development
- Educators teaching SSDLC principles
- Security professionals demonstrating testing methodologies
- Researchers studying security testing effectiveness

---

## Repository Structure

```
RSA-Trial-/
├── .github/
│   └── workflows/
│       └── security-tests.yml           # CI/CD pipeline for automated testing
├── RSA-JavaSpringboot/                  # Main Java Spring Boot implementation
│   ├── src/
│   │   ├── main/java/                   # Application source code
│   │   │   └── com/example/rsa/
│   │   │       ├── controller/          # REST API controllers
│   │   │       ├── service/             # Business logic (encryption, audit)
│   │   │       ├── model/               # JPA entities
│   │   │       ├── repository/          # Data access layer
│   │   │       └── util/                # Utilities (JWT, crypto helpers)
│   │   └── test/java/                   # Test suites
│   │       └── com/example/rsa/
│   │           └── security/
│   │               ├── VulnerabilityDemonstrationTest.java
│   │               └── SecureImplementationTest.java
│   ├── pom.xml                          # Maven dependencies and build config
│   ├── client.py                        # Python CLI client for testing
│   └── README.md                        # Implementation-specific documentation
├── QUESTION_6_THEORY_FOR_REPORT.md      # Theoretical content for report writing
├── SECURITY_TEST_RESULTS.md             # Detailed test results and findings
├── SECURITY_TESTING_STRATEGY.md         # Testing strategy and compliance
├── README.md                            # This file (project overview)
└── .gitignore                           # Git ignore rules
```

---

## Continuous Integration

The project includes automated security testing through GitHub Actions:

**Workflow**: `.github/workflows/security-tests.yml`

**Pipeline Jobs**:
1. **Vulnerability Detection Tests** - Runs tests that detect security flaws (expected to fail)
2. **Secure Implementation Tests** - Validates correct security practices (expected to pass)
3. **Combined Reporting** - Aggregates results and provides educational context

The CI pipeline runs on every push and pull request, ensuring continuous security validation throughout the development process.

---

## Standards and Compliance

This project demonstrates compliance with industry standards:

- **NIST SP 800-131A** - Cryptographic algorithm and key length requirements
- **NIST SP 800-56B** - Key establishment procedures  
- **NIST SP 800-57** - Key management guidelines
- **OWASP Top 10 2021** - Web application security risks (A01, A02, A05)
- **OWASP API Security Top 10 2023** - API-specific security concerns
- **PCI-DSS 4.0** - Strong cryptography requirements
- **HIPAA Security Rule** - PHI protection standards

Detailed compliance mapping available in SECURITY_TESTING_STRATEGY.md and QUESTION_6_THEORY_FOR_REPORT.md.

---

## License

Educational use only - Academic Project

This project is provided for educational and academic purposes. It is not licensed for production deployment or commercial use.

---

## Author

Aasmant - University SSDLC Case Study Project

---

## Acknowledgments

- National Institute of Standards and Technology (NIST) for cryptographic standards
- Open Web Application Security Project (OWASP) for security testing frameworks  
- Academic advisors for guidance on security testing methodology
- Spring Boot and Spring Security teams for framework support
