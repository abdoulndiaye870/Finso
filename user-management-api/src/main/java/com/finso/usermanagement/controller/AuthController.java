package com.finso.usermanagement.controller;

import com.finso.usermanagement.dto.AuthResponse;
import com.finso.usermanagement.dto.LoginRequest;
import com.finso.usermanagement.dto.UserRequestDto;
import com.finso.usermanagement.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Endpoints for user registration and login")
public class AuthController {

    private final UserService userService;

    @PostMapping("/register")
    @Operation(
            summary = "Register a new user",
            description = "Creates a new user account and returns a JWT access token and refresh token."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User registered successfully",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation error"),
            @ApiResponse(responseCode = "409", description = "Email already in use")
    })
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody UserRequestDto request) {
        log.info("POST /api/auth/register - email: {}", request.getEmail());
        AuthResponse response = userService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    @Operation(
            summary = "Authenticate a user",
            description = "Validates credentials and returns a JWT access token and refresh token."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation error"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("POST /api/auth/login - email: {}", request.getEmail());
        AuthResponse response = userService.login(request);
        return ResponseEntity.ok(response);
    }
}
