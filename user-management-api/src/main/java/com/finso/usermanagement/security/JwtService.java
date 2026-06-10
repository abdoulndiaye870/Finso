package com.finso.usermanagement.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtService {

    private final JwtProperties jwtProperties;

    /**
     * Extract the username (subject) from the token.
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract expiration date from the token.
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Generic claim extractor using a resolver function.
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Generate a JWT access token for the given UserDetails.
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generate a JWT access token with extra claims.
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtProperties.getExpirationMs());
    }

    /**
     * Generate a refresh token for the given UserDetails.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, jwtProperties.getRefreshExpirationMs());
    }

    /**
     * Validate a token against the provided UserDetails.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Returns true if the token has expired.
     */
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expirationMs) {
        long nowMillis = System.currentTimeMillis();
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(nowMillis))
                .expiration(new Date(nowMillis + expirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.debug("JWT token is expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.warn("Unsupported JWT token: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            log.warn("Invalid JWT signature: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty: {}", e.getMessage());
            throw e;
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
