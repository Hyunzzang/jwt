package com.example.jwt.dto;

public record LoginRequest(
        String email,
        String password
) {
}
