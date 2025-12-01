package com.journalSystem.user_service.controller;

import com.journalSystem.user_service.dto.UserDTO;
import com.journalSystem.user_service.model.Role;
import com.journalSystem.user_service.model.User;
import com.journalSystem.user_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = {"http://localhost:30000", "http://localhost:3000"})
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    public record RegisterRequest(
            String username,
            String email,
            String password,
            Role role,
            String foreignId
    ) {}

    public record LoginRequest(String username, String password) {}

    @PostMapping("/register")
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

    @PostMapping("/login")
    public ResponseEntity<UserDTO> login(@RequestBody LoginRequest req) {
        User user = authService.login(req.username(), req.password());
        if (user == null) {
            return ResponseEntity.status(401).build();
        }
        return ResponseEntity.ok(toDTO(user));
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        return authService.getUserById(id)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/user-by-foreign/{foreignId}")
    public ResponseEntity<UserDTO> getUserByForeignId(@PathVariable String foreignId) {
        return authService.getUserByForeignId(foreignId)
                .map(this::toDTO)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private UserDTO toDTO(User user) {
        return new UserDTO(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole() != null ? user.getRole().name() : null,
                user.getForeignId()
        );
    }
}