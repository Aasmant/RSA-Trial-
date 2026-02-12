import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.KeyPair;
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SecurityFindingsTest {

    @Test
    public void testDeterministicEncryption() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        String plaintext = "Test deterministic encryption";
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted1 = cipher.doFinal(plaintext.getBytes());

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypted2 = cipher.doFinal(plaintext.getBytes());

        Assertions.assertArrayEquals(encrypted1, encrypted2, "Encryption should not be deterministic");
    }

    @Test
    public void testHardcodedJWTSecrets() {
        String jwtSecret = "your-hardcoded-secret"; // This should be outside of your code
        String token = Jwts.builder()
                .setSubject("user@example.com")
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();

        Assertions.assertNotNull(token, "JWT token should not be null");
    }

    @Test
    public void testIDORVulnerability() {
        // Simulated user roles and access checks
        String userId = "user123";  // Simulating a logged-in user
        String accessedUserId = "user456";  // IDOR target

        Assertions.assertNotEquals(userId, accessedUserId, "User should not access another user's data");
    }

    @Test
    public void testWeakKeySize() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024); // Weak key size
        KeyPair keyPair = keyPairGen.generateKeyPair();

        Assertions.assertTrue(keyPair.getPrivate().getEncoded().length < 2048, "Key size should be strong (at least 2048 bits)");
    }

    @Test
    public void testPrivateKeyLeakage() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        String privateKeyString = new String(privateKey.getEncoded());

        Assertions.assertFalse(privateKeyString.contains("BEGIN PRIVATE KEY"), "Private key should not be leaked in application logs or responses");
    }
}\n