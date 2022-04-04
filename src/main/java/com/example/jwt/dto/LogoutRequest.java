package com.example.jwt.dto;

public record LogoutRequest(
        String accessToken,
        String refreshToken
) {
}
