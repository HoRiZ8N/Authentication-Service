package com.example.authservice.exception;

public class DuplicateResourceException extends RuntimeException {

  public DuplicateResourceException(String resource, String field) {
    super(resource + " with this " + field + " already exist");
  }
}
