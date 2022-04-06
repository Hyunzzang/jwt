package com.example.jwt.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 참고 : https://github.com/jwtk/jjwt
 */
public class JjwtTest {
    final String SECRET_KEY = "VlwEyVBsYt9V7zq57TejMnVUyzblYcfPQye08f7MGVA9XkHN";
    final Key key =  Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));

    @Test
    public void creatingEncrypter_Test() {

        // setClaims 세팅시 setSubject로 세팅 하면 안됨. setClaims map 안에 "subject"키로 세팅 해야함.
        String token = Jwts.builder()
                .setSubject("test0001")
                .claim("email", "test0001@google.com")
                .claim("name", "hyun zzang")
                .setExpiration(addMinuteTime(60))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        System.out.println("token: " + token);

        assertThat(token).isNotNull();
    }

    @Test
    public void parsingToken_test() {
        String token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0MDAwMSIsImVtYWlsIjoidGVzdDAwMDFAZ29vZ2xlLmNvbSIsIm5hbWUiOiJoeXVuIHp6YW5nIiwiZXhwIjoxNjQ5MjE1Mjc2fQ.NMZd0gooAvPQlxDa6rgTHGafcbkYczRO4RRDe83MzUM";
        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();

        String subject = claims.getSubject();
        String email = (String) claims.get("email");
        String name = (String) claims.get("name");

        assertThat(subject).isEqualTo("test0001");
        assertThat(email).isEqualTo("test0001@google.com");
        assertThat(name).isEqualTo("hyun zzang");
    }


    private Date addMinuteTime(int minute) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(Instant.now().toEpochMilli());
        calendar.add(Calendar.MINUTE, minute);

        return calendar.getTime();
    }
}
