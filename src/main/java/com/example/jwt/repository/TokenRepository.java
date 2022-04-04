package com.example.jwt.repository;

import com.example.jwt.dto.TokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.concurrent.TimeUnit;

@Repository
@RequiredArgsConstructor
public class TokenRepository {

    private final RedisTemplate redisTemplate;


    public void saveRefreshToken(String userName, TokenInfo tokenInfo) {
        redisTemplate.opsForValue().set("TOKEN:" + userName, tokenInfo.refreshToken(), tokenInfo.refreshTokenExpire(), TimeUnit.MINUTES);
    }
}
