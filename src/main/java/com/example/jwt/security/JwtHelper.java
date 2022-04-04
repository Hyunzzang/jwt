package com.example.jwt.security;

import com.example.jwt.dto.TokenInfo;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtHelper {
    private static final String SECRET_KEY = "secretkey";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public String createJwtForClaims(String subject, Map<String, String> claims) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(Instant.now().toEpochMilli());
        calendar.add(Calendar.HOUR, 3);

        return Jwts.builder()
                .setSubject(subject)
                .setClaims(claims)
                .setExpiration(calendar.getTime())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public TokenInfo generateToken(Authentication authentication) {
        // 권한정보
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        log.info("authorities: {}", authorities);

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("email", authentication.getName())
                .setExpiration(addMinuteTime(60 * 1))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        String refreshToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("email", authentication.getName())
                .setExpiration(addMinuteTime(60 * 24 * 7))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        return new TokenInfo(accessToken, refreshToken, 60 * 24 * 7);
    }

    private Date addMinuteTime(int minute) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(Instant.now().toEpochMilli());
        calendar.add(Calendar.MINUTE, minute);

        return calendar.getTime();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }
}
