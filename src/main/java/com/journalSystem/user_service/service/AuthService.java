package com.journalSystem.user_service.service;

import com.journalSystem.user_service.model.Role;
import com.journalSystem.user_service.model.User;
import com.journalSystem.user_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;

    /**
     * Legacy register method - for non-Keycloak registration
     */
    public User register(String username, String email, String password, Role role, String foreignId) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken");
        }

        if (foreignId != null && userRepository.findByForeignId(foreignId).isPresent()) {
            throw new IllegalArgumentException("This person is already registered");
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password);
        user.setRole(role);
        user.setForeignId(foreignId);

        return userRepository.save(user);
    }

    /**
     * Setup profile for Keycloak-authenticated users
     * Called after user registers/logs in via Keycloak for the first time
     */
    public User setupProfile(String keycloakId, String username, String email,
                             Role role, String foreignId, String firstName, String lastName) {
        // Check if user already exists with this keycloakId
        Optional<User> existingUser = userRepository.findByKeycloakId(keycloakId);
        if (existingUser.isPresent()) {
            // User already set up, return existing
            return existingUser.get();
        }

        // Check if foreignId is already linked to another user
        if (foreignId != null && userRepository.findByForeignId(foreignId).isPresent()) {
            throw new IllegalArgumentException("This person is already registered");
        }

        // Check if username is taken (by non-Keycloak user)
        if (userRepository.existsByUsername(username)) {
            // Generate unique username by appending keycloakId suffix
            username = username + "_" + keycloakId.substring(0, 8);
        }

        User user = new User();
        user.setKeycloakId(keycloakId);
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(null); // No password needed - Keycloak handles auth
        user.setRole(role);
        user.setForeignId(foreignId);

        return userRepository.save(user);
    }

    /**
     * Get user by Keycloak ID
     */
    public Optional<User> getUserByKeycloakId(String keycloakId) {
        return userRepository.findByKeycloakId(keycloakId);
    }

    /**
     * Check if user has completed profile setup
     */
    public boolean isProfileComplete(String keycloakId) {
        Optional<User> user = userRepository.findByKeycloakId(keycloakId);
        if (user.isEmpty()) {
            return false;
        }
        // Profile is complete if user has role and foreignId
        User u = user.get();
        return u.getRole() != null && u.getForeignId() != null;
    }

    public User login(String username, String password) {
        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty() || !userOpt.get().getPassword().equals(password)) {
            return null;
        }
        return userOpt.get();
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public Optional<User> getUserByForeignId(String foreignId) {
        return userRepository.findByForeignId(foreignId);
    }
}