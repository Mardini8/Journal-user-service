package com.journalSystem.user_service.controller;

import com.journalSystem.user_service.dto.UserDTO;
import com.journalSystem.user_service.model.Role;
import com.journalSystem.user_service.model.User;
import com.journalSystem.user_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {
        "http://localhost:30000",
        "http://localhost:3000",
        "https://patientsystem-frontend.app.cloud.cbh.kth.se"
})
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    // === Request Records ===

    public record RegisterRequest(
            String username,
            String email,
            String password,
            Role role,
            String foreignId
    ) {}

    public record LoginRequest(String username, String password) {}

    public record SetupProfileRequest(
            String keycloakId,
            String username,
            String email,
            String role,
            String foreignId,
            String firstName,
            String lastName
    ) {}

    // === Legacy Auth Endpoints (for non-Keycloak) ===

    @PostMapping("/v1/auth/register")
    public ResponseEntity<UserDTO> register(@RequestBody RegisterRequest req) {
        try {
            User user = authService.register(
                    req.username(),
                    req.email(),
                    req.password(),
                    req.role(),
                    req.foreignId()
            );
            return ResponseEntity.ok(toDTO(user));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/v1/auth/login")
    public ResponseEntity<UserDTO> login(@RequestBody LoginRequest req) {
        User user = authService.login(req.username(), req.password());
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(toDTO(user));
    }

    // === Keycloak Profile Setup Endpoint ===

    @PostMapping("/users/setup-profile")
    public ResponseEntity<?> setupProfile(@RequestBody SetupProfileRequest req) {
        try {
            // Convert role string to enum
            Role role;
            try {
                role = Role.valueOf(req.role().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body("Invalid role: " + req.role());
            }

            User user = authService.setupProfile(
                    req.keycloakId(),
                    req.username(),
                    req.email(),
                    role,
                    req.foreignId(),
                    req.firstName(),
                    req.lastName()
            );
            return ResponseEntity.ok(toDTO(user));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error setting up profile: " + e.getMessage());
        }
    }

    // === User Lookup Endpoints ===

    @GetMapping("/v1/auth/user/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        return authService.getUserById(id)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/v1/auth/user-by-foreign/{foreignId}")
    public ResponseEntity<UserDTO> getUserByForeignId(@PathVariable String foreignId) {
        return authService.getUserByForeignId(foreignId)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/users/keycloak/{keycloakId}")
    public ResponseEntity<UserDTO> getUserByKeycloakId(@PathVariable String keycloakId) {
        return authService.getUserByKeycloakId(keycloakId)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/users/keycloak/{keycloakId}/profile-complete")
    public ResponseEntity<Boolean> isProfileComplete(@PathVariable String keycloakId) {
        boolean complete = authService.isProfileComplete(keycloakId);
        return ResponseEntity.ok(complete);
    }

    // === Helper Methods ===

    private UserDTO toDTO(User user) {
        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole() != null ? user.getRole().name() : null,
                user.getForeignId(),
                user.getKeycloakId()
        );
    }
}