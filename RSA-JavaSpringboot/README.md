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
