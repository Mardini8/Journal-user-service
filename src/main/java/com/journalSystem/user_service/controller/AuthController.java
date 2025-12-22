package com.journalSystem.user_service.controller;

import com.journalSystem.user_service.dto.UserDTO;
import com.journalSystem.user_service.model.Role;
import com.journalSystem.user_service.model.User;
import com.journalSystem.user_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
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

    // === Public Endpoints (no auth required) ===

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

    // === Authenticated Endpoints (requires valid JWT) ===

    /**
     * Setup profile - called after Keycloak login/registration
     * Any authenticated user can call this (to set up their own profile)
     */
    @PostMapping("/users/setup-profile")
    public ResponseEntity<?> setupProfile(
            @RequestBody SetupProfileRequest req,
            @AuthenticationPrincipal Jwt jwt) {

        // Verify the keycloakId in request matches the authenticated user
        String authenticatedUserId = jwt.getSubject();
        if (!authenticatedUserId.equals(req.keycloakId())) {
            return ResponseEntity.status(403).body("Cannot setup profile for another user");
        }

        try {
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

    /**
     * Get current user's profile based on JWT
     */
    @GetMapping("/users/me")
    public ResponseEntity<UserDTO> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        String keycloakId = jwt.getSubject();
        return authService.getUserByKeycloakId(keycloakId)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Get user by Keycloak ID
     * Authenticated users can look up their own profile
     */
    @GetMapping("/users/keycloak/{keycloakId}")
    public ResponseEntity<UserDTO> getUserByKeycloakId(
            @PathVariable String keycloakId,
            @AuthenticationPrincipal Jwt jwt) {

        // Users can only look up their own keycloak profile (unless admin/doctor)
        String authenticatedUserId = jwt.getSubject();
        boolean isOwnProfile = authenticatedUserId.equals(keycloakId);
        boolean hasElevatedAccess = hasRole(jwt, "DOCTOR") || hasRole(jwt, "STAFF");

        if (!isOwnProfile && !hasElevatedAccess) {
            return ResponseEntity.status(403).build();
        }

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

    // === Role-Protected Endpoints ===

    /**
     * Get user by ID - Only doctors and staff can look up other users
     */
    @GetMapping("/v1/auth/user/{id}")
    @PreAuthorize("hasAnyRole('DOCTOR', 'STAFF')")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        return authService.getUserById(id)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Get user by foreign ID (personnummer) - Only doctors and staff
     */
    @GetMapping("/v1/auth/user-by-foreign/{foreignId}")
    @PreAuthorize("hasAnyRole('DOCTOR', 'STAFF')")
    public ResponseEntity<UserDTO> getUserByForeignId(@PathVariable String foreignId) {
        return authService.getUserByForeignId(foreignId)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * Get all users - Only doctors and staff
     */
    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('DOCTOR', 'STAFF')")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        List<UserDTO> users = authService.getAllUsers().stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
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

    private boolean hasRole(Jwt jwt, String role) {
        var realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) realmAccess.get("roles");
            return roles.stream().anyMatch(r -> r.equalsIgnoreCase(role));
        }
        return false;
    }
}