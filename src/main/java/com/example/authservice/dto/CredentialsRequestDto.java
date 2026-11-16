package com.example.authservice.dto;

import com.example.authservice.security.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record CredentialsRequestDto(
    @NotNull @Positive Long userId,
    @NotBlank @Size(min = 3, max = 255)
    @Pattern(regexp = "^[a-zA-Z0-9._@-]+$",
        message = "may contain only letters, digits and . _ @ -") String login,
    @NotBlank @Size(min = 8, max = 128) String password,
    @NotNull Role role) {
}
