package com.example.authservice.service;

import com.example.authservice.dto.LoginRequestDto;
import com.example.authservice.dto.RefreshTokenRequestDto;
import com.example.authservice.dto.TokenResponseDto;
import com.example.authservice.dto.TokenValidationDto;
import com.example.authservice.dto.ValidateTokenRequestDto;

public interface AuthService {

  TokenResponseDto login(LoginRequestDto request);

  TokenResponseDto refresh(RefreshTokenRequestDto request);

  TokenValidationDto validate(ValidateTokenRequestDto request);
}
