package com.journalSystem.user_service.dto;

public record UserDTO(
        Long id,
        String username,
        String email,
        String role,
        String foreignId,
        String keycloakId
) {}