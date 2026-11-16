package com.example.authservice.service;

import com.example.authservice.dto.CredentialsRequestDto;
import com.example.authservice.dto.CredentialsResponseDto;

public interface CredentialService {

  CredentialsResponseDto save(CredentialsRequestDto request);
}
