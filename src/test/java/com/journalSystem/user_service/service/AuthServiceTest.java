package com.journalSystem.user_service.service;

import com.journalSystem.user_service.model.Role;
import com.journalSystem.user_service.model.User;
import com.journalSystem.user_service.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private AuthService authService;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = createTestUser(1L, "testuser", "test@example.com",
                "password123", Role.PATIENT, "197001011234");
    }

    // register() TESTS

    @Test
    void register_shouldCreateAndReturnUser_whenValidData() {
        // Arrange
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.findByForeignId("197001011234")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(1L);
            return user;
        });

        // Act
        User result = authService.register("newuser", "new@example.com",
                "password", Role.PATIENT, "197001011234");

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("newuser");
        assertThat(result.getEmail()).isEqualTo("new@example.com");
        assertThat(result.getPassword()).isEqualTo("password");
        assertThat(result.getRole()).isEqualTo(Role.PATIENT);
        assertThat(result.getForeignId()).isEqualTo("197001011234");

        verify(userRepository).existsByUsername("newuser");
        verify(userRepository).findByForeignId("197001011234");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_shouldThrowException_whenUsernameExists() {
        // Arrange
        when(userRepository.existsByUsername("existinguser")).thenReturn(true);

        // Act & Assert
        assertThatThrownBy(() -> authService.register("existinguser", "email@test.com",
                "password", Role.PATIENT, "197001011234"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Username already taken");

        verify(userRepository).existsByUsername("existinguser");
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_shouldThrowException_whenForeignIdExists() {
        // Arrange
        String existingForeignId = "197001011234";
        when(userRepository.existsByUsername("newuser")).thenReturn(false);
        when(userRepository.findByForeignId(existingForeignId)).thenReturn(Optional.of(testUser));

        // Act & Assert
        assertThatThrownBy(() -> authService.register("newuser", "email@test.com",
                "password", Role.PATIENT, existingForeignId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("This person is already registered");

        verify(userRepository).existsByUsername("newuser");
        verify(userRepository).findByForeignId(existingForeignId);
        verify(userRepository, never()).save(any());
    }

    @Test
    void register_shouldAllowNullForeignId() {
        // Arrange
        when(userRepository.existsByUsername("staffuser")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(2L);
            return user;
        });

        // Act
        User result = authService.register("staffuser", "staff@example.com",
                "password", Role.STAFF, null);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getForeignId()).isNull();

        verify(userRepository).existsByUsername("staffuser");
        verify(userRepository, never()).findByForeignId(any());
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_shouldCreateDoctorUser() {
        // Arrange
        when(userRepository.existsByUsername("doctor")).thenReturn(false);
        when(userRepository.findByForeignId("198001011234")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(3L);
            return user;
        });

        // Act
        User result = authService.register("doctor", "doctor@hospital.com",
                "password", Role.DOCTOR, "198001011234");

        // Assert
        assertThat(result.getRole()).isEqualTo(Role.DOCTOR);
        assertThat(result.getForeignId()).isEqualTo("198001011234");
    }

    @Test
    void register_shouldCreateStaffUser() {
        // Arrange
        when(userRepository.existsByUsername("staff")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(4L);
            return user;
        });

        // Act
        User result = authService.register("staff", "staff@hospital.com",
                "password", Role.STAFF, null);

        // Assert
        assertThat(result.getRole()).isEqualTo(Role.STAFF);
        assertThat(result.getForeignId()).isNull();
    }

    @Test
    void register_shouldHandleEmptyEmail() {
        // Arrange
        when(userRepository.existsByUsername("user")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(5L);
            return user;
        });

        // Act
        User result = authService.register("user", "", "password", Role.PATIENT, null);

        // Assert
        assertThat(result.getEmail()).isEmpty();
    }

    @Test
    void register_shouldHandleNullEmail() {
        // Arrange
        when(userRepository.existsByUsername("user")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(6L);
            return user;
        });

        // Act
        User result = authService.register("user", null, "password", Role.PATIENT, null);

        // Assert
        assertThat(result.getEmail()).isNull();
    }

    @Test
    void register_shouldHandleSpecialCharactersInUsername() {
        // Arrange
        String specialUsername = "user.name_123";
        when(userRepository.existsByUsername(specialUsername)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(7L);
            return user;
        });

        // Act
        User result = authService.register(specialUsername, "email@test.com",
                "password", Role.PATIENT, null);

        // Assert
        assertThat(result.getUsername()).isEqualTo(specialUsername);
    }

    // login() TESTS

    @Test
    void login_shouldReturnUser_whenCredentialsCorrect() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Act
        User result = authService.login("testuser", "password123");

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("testuser");
        assertThat(result.getEmail()).isEqualTo("test@example.com");

        verify(userRepository).findByUsername("testuser");
    }

    @Test
    void login_shouldReturnNull_whenUsernameNotFound() {
        // Arrange
        when(userRepository.findByUsername("nonexistent")).thenReturn(Optional.empty());

        // Act
        User result = authService.login("nonexistent", "password");

        // Assert
        assertThat(result).isNull();

        verify(userRepository).findByUsername("nonexistent");
    }

    @Test
    void login_shouldReturnNull_whenPasswordIncorrect() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Act
        User result = authService.login("testuser", "wrongpassword");

        // Assert
        assertThat(result).isNull();

        verify(userRepository).findByUsername("testuser");
    }

    @Test
    void login_shouldReturnNull_whenPasswordIsNull() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Act
        User result = authService.login("testuser", null);

        // Assert
        assertThat(result).isNull();
    }

    @Test
    void login_shouldReturnNull_whenPasswordIsEmpty() {
        // Arrange
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(testUser));

        // Act
        User result = authService.login("testuser", "");

        // Assert
        assertThat(result).isNull();
    }

    @Test
    void login_shouldBeCaseSensitive() {
        // Arrange
        when(userRepository.findByUsername("TestUser")).thenReturn(Optional.empty());

        // Act
        User result = authService.login("TestUser", "password123");

        // Assert
        assertThat(result).isNull();

        verify(userRepository).findByUsername("TestUser");
    }

    @Test
    void login_shouldWorkForDifferentRoles() {
        // Arrange - Test DOCTOR login
        User doctorUser = createTestUser(2L, "doctor", "doctor@test.com",
                "pass", Role.DOCTOR, "198001011234");
        when(userRepository.findByUsername("doctor")).thenReturn(Optional.of(doctorUser));

        // Act
        User result = authService.login("doctor", "pass");

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getRole()).isEqualTo(Role.DOCTOR);
    }

    // getUserById() TESTS

    @Test
    void getUserById_shouldReturnUser_whenUserExists() {
        // Arrange
        when(userRepository.findById(1L)).thenReturn(Optional.of(testUser));

        // Act
        Optional<User> result = authService.getUserById(1L);

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(1L);
        assertThat(result.get().getUsername()).isEqualTo("testuser");

        verify(userRepository).findById(1L);
    }

    @Test
    void getUserById_shouldReturnEmpty_whenUserNotFound() {
        // Arrange
        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        // Act
        Optional<User> result = authService.getUserById(999L);

        // Assert
        assertThat(result).isEmpty();

        verify(userRepository).findById(999L);
    }

    @Test
    void getUserById_shouldReturnEmpty_whenIdIsNull() {
        // Arrange
        when(userRepository.findById(null)).thenReturn(Optional.empty());

        // Act
        Optional<User> result = authService.getUserById(null);

        // Assert
        assertThat(result).isEmpty();

        verify(userRepository).findById(null);
    }

    @Test
    void getUserById_shouldHandleDifferentUsers() {
        // Arrange
        User user1 = createTestUser(1L, "user1", "user1@test.com", "pass", Role.PATIENT, "111");
        User user2 = createTestUser(2L, "user2", "user2@test.com", "pass", Role.DOCTOR, "222");
        User user3 = createTestUser(3L, "user3", "user3@test.com", "pass", Role.STAFF, null);

        when(userRepository.findById(1L)).thenReturn(Optional.of(user1));
        when(userRepository.findById(2L)).thenReturn(Optional.of(user2));
        when(userRepository.findById(3L)).thenReturn(Optional.of(user3));

        // Act & Assert
        assertThat(authService.getUserById(1L)).isPresent();
        assertThat(authService.getUserById(2L)).isPresent();
        assertThat(authService.getUserById(3L)).isPresent();
    }

    // getUserByForeignId() TESTS

    @Test
    void getUserByForeignId_shouldReturnUser_whenForeignIdExists() {
        // Arrange
        when(userRepository.findByForeignId("197001011234")).thenReturn(Optional.of(testUser));

        // Act
        Optional<User> result = authService.getUserByForeignId("197001011234");

        // Assert
        assertThat(result).isPresent();
        assertThat(result.get().getForeignId()).isEqualTo("197001011234");
        assertThat(result.get().getUsername()).isEqualTo("testuser");

        verify(userRepository).findByForeignId("197001011234");
    }

    @Test
    void getUserByForeignId_shouldReturnEmpty_whenForeignIdNotFound() {
        // Arrange
        when(userRepository.findByForeignId("999999999999")).thenReturn(Optional.empty());

        // Act
        Optional<User> result = authService.getUserByForeignId("999999999999");

        // Assert
        assertThat(result).isEmpty();

        verify(userRepository).findByForeignId("999999999999");
    }

    @Test
    void getUserByForeignId_shouldReturnEmpty_whenForeignIdIsNull() {
        // Arrange
        when(userRepository.findByForeignId(null)).thenReturn(Optional.empty());

        // Act
        Optional<User> result = authService.getUserByForeignId(null);

        // Assert
        assertThat(result).isEmpty();

        verify(userRepository).findByForeignId(null);
    }

    @Test
    void getUserByForeignId_shouldHandleDifferentFormats() {
        // Arrange
        String[] personnummerFormats = {
                "197001011234",
                "19700101-1234",
                "700101-1234"
        };

        for (String foreignId : personnummerFormats) {
            User user = createTestUser(1L, "user", "user@test.com", "pass", Role.PATIENT, foreignId);
            when(userRepository.findByForeignId(foreignId)).thenReturn(Optional.of(user));

            // Act
            Optional<User> result = authService.getUserByForeignId(foreignId);

            // Assert
            assertThat(result).isPresent();
            assertThat(result.get().getForeignId()).isEqualTo(foreignId);
        }
    }

    // INTEGRATION TESTS

    @Test
    void register_thenGetByIdAndForeignId_shouldWork() {
        // Arrange
        when(userRepository.existsByUsername("integrated")).thenReturn(false);
        when(userRepository.findByForeignId("197001011234")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(10L);
            return user;
        });

        // Act - Register
        User registered = authService.register("integrated", "int@test.com",
                "password", Role.PATIENT, "197001011234");

        // Setup mocks for retrieval
        when(userRepository.findById(10L)).thenReturn(Optional.of(registered));
        when(userRepository.findByForeignId("197001011234")).thenReturn(Optional.of(registered));

        // Act - Get by ID
        Optional<User> byId = authService.getUserById(10L);

        // Act - Get by Foreign ID
        Optional<User> byForeignId = authService.getUserByForeignId("197001011234");

        // Assert
        assertThat(byId).isPresent();
        assertThat(byForeignId).isPresent();
        assertThat(byId.get().getId()).isEqualTo(byForeignId.get().getId());
    }

    @Test
    void register_thenLogin_shouldWork() {
        // Arrange
        String username = "logintest";
        String password = "secret";

        when(userRepository.existsByUsername(username)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(11L);
            return user;
        });

        // Act - Register
        User registered = authService.register(username, "login@test.com",
                password, Role.PATIENT, "197001011234");

        // Setup mock for login
        when(userRepository.findByUsername(username)).thenReturn(Optional.of(registered));

        // Act - Login
        User loggedIn = authService.login(username, password);

        // Assert
        assertThat(loggedIn).isNotNull();
        assertThat(loggedIn.getUsername()).isEqualTo(username);
        assertThat(loggedIn.getId()).isEqualTo(11L);
    }

    // EDGE CASES

    @Test
    void register_shouldHandleLongUsername() {
        // Arrange
        String longUsername = "a".repeat(100);
        when(userRepository.existsByUsername(longUsername)).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(12L);
            return user;
        });

        // Act
        User result = authService.register(longUsername, "email@test.com",
                "password", Role.PATIENT, null);

        // Assert
        assertThat(result.getUsername()).hasSize(100);
    }

    @Test
    void register_shouldHandleLongPassword() {
        // Arrange
        String longPassword = "p".repeat(200);
        when(userRepository.existsByUsername("user")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(13L);
            return user;
        });

        // Act
        User result = authService.register("user", "email@test.com",
                longPassword, Role.PATIENT, null);

        // Assert
        assertThat(result.getPassword()).hasSize(200);
    }

    @Test
    void register_shouldHandleSpecialCharactersInEmail() {
        // Arrange
        String specialEmail = "user+test@example.co.uk";
        when(userRepository.existsByUsername("user")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(14L);
            return user;
        });

        // Act
        User result = authService.register("user", specialEmail,
                "password", Role.PATIENT, null);

        // Assert
        assertThat(result.getEmail()).isEqualTo(specialEmail);
    }

    @Test
    void login_shouldHandleWhitespaceInPassword() {
        // Arrange
        User userWithSpaces = createTestUser(1L, "user", "email@test.com",
                "pass word", Role.PATIENT, null);
        when(userRepository.findByUsername("user")).thenReturn(Optional.of(userWithSpaces));

        // Act
        User correct = authService.login("user", "pass word");
        User incorrect = authService.login("user", "password");

        // Assert
        assertThat(correct).isNotNull();
        assertThat(incorrect).isNull();
    }

    // HELPER METHODS

    private User createTestUser(Long id, String username, String email,
                                String password, Role role, String foreignId) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(password);
        user.setRole(role);
        user.setForeignId(foreignId);
        return user;
    }
}