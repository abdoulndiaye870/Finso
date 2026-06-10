package com.finso.usermanagement.service;

import com.finso.usermanagement.dto.AuthResponse;
import com.finso.usermanagement.dto.LoginRequest;
import com.finso.usermanagement.dto.PagedResponse;
import com.finso.usermanagement.dto.UpdateUserDto;
import com.finso.usermanagement.dto.UserRequestDto;
import com.finso.usermanagement.dto.UserResponseDto;
import com.finso.usermanagement.entity.Role;
import com.finso.usermanagement.entity.User;
import com.finso.usermanagement.exception.EmailAlreadyExistsException;
import com.finso.usermanagement.exception.InvalidCredentialsException;
import com.finso.usermanagement.exception.UserNotFoundException;
import com.finso.usermanagement.repository.UserRepository;
import com.finso.usermanagement.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // -------------------------------------------------------------------------
    // Auth operations
    // -------------------------------------------------------------------------

    /**
     * Register a new user and return a JWT pair.
     */
    public AuthResponse register(UserRequestDto request) {
        log.info("Registering new user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException(request.getEmail());
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() != null ? request.getRole() : Role.ROLE_USER)
                .enabled(true)
                .build();

        user = userRepository.save(user);
        log.info("User registered successfully with id: {}", user.getId());

        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return buildAuthResponse(accessToken, refreshToken, user);
    }

    /**
     * Authenticate a user by email/password and return a JWT pair.
     */
    public AuthResponse login(LoginRequest request) {
        log.info("Login attempt for email: {}", request.getEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            User user = (User) authentication.getPrincipal();
            String accessToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            log.info("User logged in successfully: {}", user.getEmail());
            return buildAuthResponse(accessToken, refreshToken, user);

        } catch (BadCredentialsException | DisabledException e) {
            log.warn("Login failed for email {}: {}", request.getEmail(), e.getMessage());
            throw new InvalidCredentialsException();
        }
    }

    // -------------------------------------------------------------------------
    // CRUD operations
    // -------------------------------------------------------------------------

    /**
     * Retrieve a page of users, with optional keyword search.
     */
    @Transactional(readOnly = true)
    public PagedResponse<UserResponseDto> getAllUsers(int page, int size, String sortBy, String direction, String keyword) {
        Sort sort = direction.equalsIgnoreCase("desc")
                ? Sort.by(sortBy).descending()
                : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);

        Page<User> userPage;
        if (StringUtils.hasText(keyword)) {
            userPage = userRepository.searchUsers(keyword.trim(), pageable);
        } else {
            userPage = userRepository.findAll(pageable);
        }

        return PagedResponse.<UserResponseDto>builder()
                .content(userPage.getContent().stream().map(this::toResponseDto).toList())
                .page(userPage.getNumber())
                .size(userPage.getSize())
                .totalElements(userPage.getTotalElements())
                .totalPages(userPage.getTotalPages())
                .last(userPage.isLast())
                .build();
    }

    /**
     * Retrieve a single user by ID.
     */
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(Long id) {
        return toResponseDto(findUserByIdOrThrow(id));
    }

    /**
     * Update an existing user. Only non-null fields are updated (partial update).
     */
    public UserResponseDto updateUser(Long id, UpdateUserDto request) {
        log.info("Updating user with id: {}", id);
        User user = findUserByIdOrThrow(id);

        if (StringUtils.hasText(request.getFirstName())) {
            user.setFirstName(request.getFirstName());
        }
        if (StringUtils.hasText(request.getLastName())) {
            user.setLastName(request.getLastName());
        }
        if (StringUtils.hasText(request.getEmail()) && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new EmailAlreadyExistsException(request.getEmail());
            }
            user.setEmail(request.getEmail());
        }
        if (StringUtils.hasText(request.getPassword())) {
            user.setPassword(passwordEncoder.encode(request.getPassword()));
        }
        if (request.getRole() != null) {
            user.setRole(request.getRole());
        }
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
        }

        user = userRepository.save(user);
        log.info("User updated successfully: {}", user.getId());
        return toResponseDto(user);
    }

    /**
     * Hard-delete a user by ID.
     */
    public void deleteUser(Long id) {
        log.info("Deleting user with id: {}", id);
        User user = findUserByIdOrThrow(id);
        userRepository.delete(user);
        log.info("User deleted: {}", id);
    }

    /**
     * Return the UserResponseDto for the currently authenticated user.
     */
    @Transactional(readOnly = true)
    public UserResponseDto getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));
        return toResponseDto(user);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private User findUserByIdOrThrow(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }

    public UserResponseDto toResponseDto(User user) {
        return UserResponseDto.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }

    private AuthResponse buildAuthResponse(String accessToken, String refreshToken, User user) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtService.extractExpiration(accessToken).getTime())
                .user(toResponseDto(user))
                .build();
    }
}
