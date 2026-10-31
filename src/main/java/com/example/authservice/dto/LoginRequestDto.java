package com.example.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequestDto(
    @NotBlank @Size(max = 255) String login,
    @NotBlank @Size(max = 128) String password) {
}
