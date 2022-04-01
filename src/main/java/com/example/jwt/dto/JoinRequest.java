package com.example.jwt.dto;

public record JoinRequest(
        String email,
        String password
) {
}