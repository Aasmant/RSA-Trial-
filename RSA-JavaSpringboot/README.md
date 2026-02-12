# RSA Encryption Service - Java Spring Boot Implementation

This is a port of the Python RSA Encryption Service to Java Spring Boot, maintaining the same functionality and intentional security vulnerabilities for educational purposes.

## Project Structure
- **Controller**: `ApiController.java` (REST Endpoints)
- **Service**: `EncryptionService.java` (RSA/AES Logic), `AuditService.java`
- **Model**: `User`, `FileEntity`, `AuditLog` (JPA Entities)
- **Database**: SQLite (`rsa_service.db`) matching the Python schema.

## Prerequisites
- Java 17+
- Maven

## How to Run

1. **Build the project**:
   ```bash
   mvn clean install
   ```

2. **Run the application**:
   ```bash
   mvn spring-boot:run
   ```
   The server will start on port `5000` (defined in `application.properties`).

3. **Use the Client**:
   The Python client is compatible with this Java backend.
   ```bash
   python3 client.py
   ```

## Intentional Vulnerabilities (Educational)
This project replicates the specific security flaws found in the Python original:
1. **Hardcoded Secret Key**: `JwtUtil.java` uses a hardcoded string.
2. **Weak Password**: Registration allows short passwords.
3. **Private Key Disclosure**: Registration returns the private key to the client.
4. **No File Size Limit**: Uploads allow large files (configured in `application.properties`).
5. **IDOR**: `decrypt` endpoint may not strictly validate file ownership in some logic paths.
6. **Weak Crypto**: Uses MD5 for some hashing operations (as placeholder/weakness).

**DO NOT USE IN PRODUCTION.**

---

## ⚠️ Security Testing Demonstration

### 🔴 Red Checks = Good Finding!

This project demonstrates **why security testing matters** by intentionally including vulnerabilities.

#### Test Suite Structure:

1. **Vulnerability Demonstration Tests** (❌ Expected to FAIL)
   - Location: `src/test/java/com/example/rsa/security/VulnerabilityDemonstrationTest.java`
   - These tests PROVE security testing can find real flaws
   - Each failure shows a specific vulnerability (IDOR, hardcoded secrets, deterministic encryption)

2. **Secure Implementation Tests** (✅ Expected to PASS)
   - Location: `src/test/java/com/example/rsa/security/SecureImplementationTest.java`
   - Demonstrates proper cryptographic practices
   - Shows OAEP padding, strong keys, secure API design

### 📖 Professor's Requirement Met:

> "Even if your unit testing would find that your own RSA textbook implementation is weak (e.g. deterministic) that would be a great observation."

✅ **See `testTextbookRSAIsDeterministic()` for this exact demonstration!**

### 🎯 Question 6 Coverage:

- **a) Comprehensive security testing strategy** ✅ Multiple SSDLC phases covered
- **b) Unit testing & static analysis role** ✅ 12 tests demonstrating vulnerability detection
- **c) Compliance requirements** ✅ Documented in SECURITY_TESTING_STRATEGY.md

### 🚀 Running the Tests

**Run all security tests:**
```bash
mvn test -Dtest="*security*"
```

**Run vulnerability detection tests (8 intentional failures):**
```bash
mvn test -Dtest=VulnerabilityDemonstrationTest
```

**Run secure implementation tests (4 passes):**
```bash
mvn test -Dtest=SecureImplementationTest
```

**Note:** Failing tests are intentional and educational. They demonstrate successful vulnerability detection, not code failures.
