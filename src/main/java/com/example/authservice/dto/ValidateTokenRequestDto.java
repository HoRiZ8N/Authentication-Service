package com.example.authservice.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequestDto(@NotBlank String token) {
}
