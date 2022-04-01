package com.example.jwt.dto;

public record TokenInfo(
        String accessToken,
        String refreshToken,
        long refreshTokenExpire
) {
}
