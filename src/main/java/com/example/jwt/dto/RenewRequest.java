package com.example.jwt.dto;

public record RenewRequest(
        String accessToken,
        String refreshToken
) {
}
