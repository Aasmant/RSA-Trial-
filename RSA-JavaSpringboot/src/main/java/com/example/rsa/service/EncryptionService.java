package com.example.rsa.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
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

    // Pure RSA chunked encryption to handle files of any size.

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

        // Pure RSA Encryption in Chunks
        // For RSA 2048 with OAEP SHA-256:
        // Max data size = KeySize (256) - 2 * HashSize (32) - 2 = 190 bytes
        // AI generated: Complex calculation for RSA-OAEP max data overhead
        int maxChunkSize = 190;
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        // AI generated: Explicit OAEP parameter spec to override default Java
        // MGF1-SHA1
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int offset = 0;
        while (offset < fileData.length) {
            int length = Math.min(maxChunkSize, fileData.length - offset);
            byte[] chunk = rsaCipher.doFinal(fileData, offset, length);
            outputStream.write(chunk);
            offset += length;
        }

        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
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

        byte[] encryptedData = Base64.getDecoder().decode(encryptedDataB64);

        // Pure RSA Decryption in Chunks
        // RSA 2048 bit output is always 256 bytes per block
        int blockSize = 256;
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int offset = 0;
        while (offset < encryptedData.length) {
            int length = Math.min(blockSize, encryptedData.length - offset);
            byte[] decryptedChunk = rsaCipher.doFinal(encryptedData, offset, length);
            outputStream.write(decryptedChunk);
            offset += length;
        }

        return outputStream.toByteArray();
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
