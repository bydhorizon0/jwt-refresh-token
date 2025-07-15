package org.jwtsimple.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtUtil {

    public static final long ACCESS_EXPIRATION_TIME = 1000L * 60 * 30;
    public static final long REFRESH_EXPIRATION_TIME = 1000L * 60 * 30;
    private final SecretKey SECRET_KEY;

    public JwtUtil(@Value("${jwt.secret-key}") String secretKey) {
        this.SECRET_KEY = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    private String generateToken(String email, long expiration) {
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .signWith(SECRET_KEY)
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .compact();
    }

    public String generateAccessToken(String email) {
        return generateToken(email, ACCESS_EXPIRATION_TIME);
    }

    public String generateRefreshToken(String email) {
        return generateToken(email, REFRESH_EXPIRATION_TIME);
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        String extractedEmail = extractEmail(token);
        return (extractedEmail.equalsIgnoreCase(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public static long calcExpiresIn(long expiration) {
        long now = System.currentTimeMillis();
        Date expiryAt = new Date(now + expiration);

        return (expiryAt.getTime() + System.currentTimeMillis() / 1000);
    }

}
