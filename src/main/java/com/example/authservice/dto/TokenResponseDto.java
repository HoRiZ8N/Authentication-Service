package com.example.authservice.dto;

public record TokenResponseDto(
    String accessToken,
    String refreshToken,
    String tokenType,
    long expiresIn,
    long refreshExpiresIn) {
}
