package com.example.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.dto.TokenInfo;
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

        JWTCreator.Builder jwtBuilder = JWT.create().withSubject(subject);

        claims.forEach(jwtBuilder::withClaim);

        return jwtBuilder
                .withNotBefore(new Date())
                .withExpiresAt(calendar.getTime())
                .sign(Algorithm.RSA256(publicKey, privateKey));
    }

    public TokenInfo generateToken(Authentication authentication) {
        // 권한정보
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        log.info("authorities: {}", authorities);

        JWTCreator.Builder jwtBuilder = JWT.create().withSubject(authentication.getName());
        String accessToken = jwtBuilder
                .withNotBefore(new Date())
                .withExpiresAt(addMinuteTime(60))
                .sign(Algorithm.RSA256(publicKey, privateKey));

        String refreshToken = jwtBuilder
                .withNotBefore(new Date())
                .withExpiresAt(addMinuteTime(60 * 24 * 7))
                .sign(Algorithm.RSA256(publicKey, privateKey));

        return new TokenInfo(accessToken, refreshToken, 60 * 24 * 7);
    }

    private Date addMinuteTime(int minute) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(Instant.now().toEpochMilli());
        calendar.add(Calendar.MINUTE, minute);

        return calendar.getTime();
    }
}
