package com.example.jwt.repository;

import com.example.jwt.dto.TokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@Repository
@RequiredArgsConstructor
public class TokenRepository {

    private final RedisTemplate<String, String> redisTemplate;


    public void saveRefreshToken(String userName, TokenInfo tokenInfo) {
        redisTemplate.opsForValue().set(makeRefreshTokenKey(userName), tokenInfo.refreshToken(), tokenInfo.refreshTokenExpire(), TimeUnit.MINUTES);
    }

    public String findRefreshToken(String userName) {
        return redisTemplate.opsForValue().get(makeRefreshTokenKey(userName));
    }

    public boolean deleteRefreshToken(String userName) {
        return redisTemplate.delete(makeRefreshTokenKey(userName));
    }

    public void saveLogoutToken(String accessToken, Long expiration) {
        redisTemplate.opsForValue().set(makeLogoutKey(accessToken), "logout", expiration, TimeUnit.MILLISECONDS);
    }

    public boolean existsLogout(String accessToken) {
        return redisTemplate.hasKey(makeLogoutKey(accessToken));
    }

    public String findLogoutToken(String accessToken) {
        return redisTemplate.opsForValue().get(makeLogoutKey(accessToken));
    }

    private String makeRefreshTokenKey(String userName) {
        return String.format("TOKEN:%s", userName);
    }

    private String makeLogoutKey(String accessToken) {
        return String.format("TOKEN:LOGOUT:%S", accessToken);
    }
}
