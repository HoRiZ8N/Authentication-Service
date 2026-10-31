package com.example.authservice.dto;

import com.example.authservice.security.Role;
import java.time.Instant;

public record TokenValidationDto(Long userId, Role role, Instant expiresAt) {
}
