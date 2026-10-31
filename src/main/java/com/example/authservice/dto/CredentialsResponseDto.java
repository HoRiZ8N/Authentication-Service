package com.example.authservice.dto;

import com.example.authservice.security.Role;

public record CredentialsResponseDto(Long userId, String login, Role role) {
}
