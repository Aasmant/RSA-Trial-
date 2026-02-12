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

