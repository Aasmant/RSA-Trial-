package com.example.rsa.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    // VULNERABILITY 1: Hard-coded SECRET_KEY in source code
    // Matching the Python code: SECRET_KEY =
    // "super-secret-key-hardcoded-vulnerability"
    private static final String SECRET_KEY_STRING = "super-secret-key-hardcoded-vulnerability";
    private final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET_KEY_STRING.getBytes(StandardCharsets.UTF_8));
    // Note: HS256 requires 32 bytes minimum. If the string is too short, we might
    // need padding or use a different generation method to strictly match python's
    // weak key usage.
    // Python's jwt library might accept shorter keys. JJWT matches spec strictly.
    // To match Python logic exactly, let's use the exact string bytes.

    // However, JJWT enforces strong keys. To intentionally allow weak keys (if we
    // really want to replicate), we might suppress standard checks or just ensure
    // the string is long enough.
    // "super-secret-key-hardcoded-vulnerability" is 40 chars, which is > 32 bytes,
    // so it's valid for HS256.

    public String generateToken(Long userId) {
        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    public Long validateTokenAndGetUserId(String token) {
        if (token == null)
            return null;
        try {
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return Long.parseLong(claims.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            return null;
        }
    }
}
