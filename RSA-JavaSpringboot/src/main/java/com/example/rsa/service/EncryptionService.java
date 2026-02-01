package com.example.rsa.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

@Service
public class EncryptionService {
    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    // VULNERABILITY: This implementation matches the Python code's hybrid
    // encryption

    public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public String encryptFile(byte[] fileData, String publicKeyPem) throws Exception {
        // Parse Public Key
        String pem = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // Generate AES Key and IV
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Encrypt File with AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encryptedFile = aesCipher.doFinal(fileData);

        // Encrypt AES Key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // Java's default MGF1 uses SHA-1 usually, but let's try to match Python's
        // explicit SHA256 if possible or stick to standard
        // Python code uses: padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
        // algorithm=hashes.SHA256(), label=None)

        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        // Combine: encrypted_aes_key (256 bytes) + iv (16 bytes) + encrypted_file
        byte[] combined = new byte[encryptedAesKey.length + iv.length + encryptedFile.length];
        System.arraycopy(encryptedAesKey, 0, combined, 0, encryptedAesKey.length);
        System.arraycopy(iv, 0, combined, encryptedAesKey.length, iv.length);
        System.arraycopy(encryptedFile, 0, combined, encryptedAesKey.length + iv.length, encryptedFile.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public byte[] decryptFile(String encryptedDataB64, String privateKeyPem) throws Exception {
        // Parse Private Key
        String pem = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        byte[] combined = Base64.getDecoder().decode(encryptedDataB64);

        // Extract components
        // RSA 2048 bit = 256 bytes
        int keyLength = 256;
        int ivLength = 16;

        byte[] encryptedAesKey = new byte[keyLength];
        byte[] iv = new byte[ivLength];
        byte[] encryptedFile = new byte[combined.length - keyLength - ivLength];

        System.arraycopy(combined, 0, encryptedAesKey, 0, keyLength);
        System.arraycopy(combined, keyLength, iv, 0, ivLength);
        System.arraycopy(combined, keyLength + ivLength, encryptedFile, 0, encryptedFile.length);

        // Decrypt AES key with RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Decrypt file with AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        return aesCipher.doFinal(encryptedFile);
    }

    public String serializePublicKey(PublicKey publicKey) {
        String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----";
    }

    public String serializePrivateKey(PrivateKey privateKey) {
        String encoded = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----";
    }
}
