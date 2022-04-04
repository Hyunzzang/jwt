package com.example.jwt.dto;

public record TokenInfo(
        String accessToken,
        String refreshToken,
        // 분단위
        long refreshTokenExpire
) {
}
