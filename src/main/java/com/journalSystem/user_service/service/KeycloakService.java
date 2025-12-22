package com.journalSystem.user_service.service;

import jakarta.annotation.PostConstruct;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class KeycloakService {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakService.class);

    @Value("${keycloak.server-url:https://patientsystem-keycloak.app.cloud.cbh.kth.se}")
    private String serverUrl;

    @Value("${keycloak.realm:patientsystem}")
    private String realm;

    @Value("${keycloak.admin.username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin.password:admin}")
    private String adminPassword;

    private Keycloak keycloak;

    @PostConstruct
    public void init() {
        try {
            this.keycloak = KeycloakBuilder.builder()
                    .serverUrl(serverUrl)
                    .realm("master")  // Admin loggar in via master realm
                    .username(adminUsername)
                    .password(adminPassword)
                    .clientId("admin-cli")
                    .build();
            logger.info("Keycloak admin client initialized for server: {}", serverUrl);
        } catch (Exception e) {
            logger.error("Failed to initialize Keycloak admin client: {}", e.getMessage());
        }
    }

    /**
     * Assign a realm role to a user in Keycloak
     * @param keycloakUserId The Keycloak user ID (sub from token)
     * @param roleName The role name (doctor, staff, patient)
     */
    public void assignRoleToUser(String keycloakUserId, String roleName) {
        if (keycloak == null) {
            logger.warn("Keycloak client not initialized, skipping role assignment");
            return;
        }

        try {
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();

            // Get user by ID
            UserResource userResource = usersResource.get(keycloakUserId);

            // Get the role
            RoleRepresentation role = realmResource.roles().get(roleName.toLowerCase()).toRepresentation();

            if (role == null) {
                logger.warn("Role '{}' not found in Keycloak realm '{}'", roleName, realm);
                return;
            }

            // Assign role to user
            userResource.roles().realmLevel().add(Collections.singletonList(role));

            logger.info("Successfully assigned role '{}' to user '{}' in Keycloak", roleName, keycloakUserId);
        } catch (Exception e) {
            logger.error("Failed to assign role '{}' to user '{}': {}", roleName, keycloakUserId, e.getMessage());
            // Don't throw - role assignment in Keycloak is optional, user-service DB is the source of truth
        }
    }

    /**
     * Remove a realm role from a user in Keycloak
     */
    public void removeRoleFromUser(String keycloakUserId, String roleName) {
        if (keycloak == null) {
            logger.warn("Keycloak client not initialized, skipping role removal");
            return;
        }

        try {
            RealmResource realmResource = keycloak.realm(realm);
            UserResource userResource = realmResource.users().get(keycloakUserId);

            RoleRepresentation role = realmResource.roles().get(roleName.toLowerCase()).toRepresentation();

            if (role != null) {
                userResource.roles().realmLevel().remove(Collections.singletonList(role));
                logger.info("Successfully removed role '{}' from user '{}' in Keycloak", roleName, keycloakUserId);
            }
        } catch (Exception e) {
            logger.error("Failed to remove role '{}' from user '{}': {}", roleName, keycloakUserId, e.getMessage());
        }
    }

    /**
     * Get user info from Keycloak by ID
     */
    public UserRepresentation getUserById(String keycloakUserId) {
        if (keycloak == null) {
            return null;
        }

        try {
            return keycloak.realm(realm).users().get(keycloakUserId).toRepresentation();
        } catch (Exception e) {
            logger.error("Failed to get user '{}' from Keycloak: {}", keycloakUserId, e.getMessage());
            return null;
        }
    }
}