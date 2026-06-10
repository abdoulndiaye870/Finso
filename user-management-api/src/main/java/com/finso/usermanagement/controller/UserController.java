package com.finso.usermanagement.controller;

import com.finso.usermanagement.dto.PagedResponse;
import com.finso.usermanagement.dto.UpdateUserDto;
import com.finso.usermanagement.dto.UserResponseDto;
import com.finso.usermanagement.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Users", description = "User management endpoints — all require a valid JWT")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    // ------------------------------------------------------------------
    // GET /api/users
    // ------------------------------------------------------------------

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    @Operation(
            summary = "List all users (paginated)",
            description = "Returns a paginated list of users. Supports keyword search across firstName, lastName, and email."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Users retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorised — missing or invalid JWT"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<PagedResponse<UserResponseDto>> getAllUsers(
            @Parameter(description = "Zero-based page index") @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Number of records per page") @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Sort field") @RequestParam(defaultValue = "id") String sortBy,
            @Parameter(description = "Sort direction: asc or desc") @RequestParam(defaultValue = "asc") String direction,
            @Parameter(description = "Optional search keyword") @RequestParam(required = false) String keyword
    ) {
        log.info("GET /api/users - page={}, size={}, sortBy={}, direction={}, keyword={}", page, size, sortBy, direction, keyword);
        return ResponseEntity.ok(userService.getAllUsers(page, size, sortBy, direction, keyword));
    }

    // ------------------------------------------------------------------
    // GET /api/users/me
    // ------------------------------------------------------------------

    @GetMapping("/me")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    @Operation(
            summary = "Get the currently authenticated user",
            description = "Returns the profile of the user identified by the Bearer token."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Current user returned",
                    content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorised")
    })
    public ResponseEntity<UserResponseDto> getCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        log.info("GET /api/users/me - user: {}", userDetails.getUsername());
        return ResponseEntity.ok(userService.getCurrentUser(userDetails.getUsername()));
    }

    // ------------------------------------------------------------------
    // GET /api/users/{id}
    // ------------------------------------------------------------------

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    @Operation(summary = "Get a user by ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User found",
                    content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorised"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<UserResponseDto> getUserById(
            @Parameter(description = "User ID", required = true) @PathVariable Long id
    ) {
        log.info("GET /api/users/{}", id);
        return ResponseEntity.ok(userService.getUserById(id));
    }

    // ------------------------------------------------------------------
    // PUT /api/users/{id}
    // ------------------------------------------------------------------

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_USER')")
    @Operation(
            summary = "Update a user",
            description = "Partial update — only non-null fields are applied. ROLE_ADMIN can update any user; "
                    + "ROLE_USER may only update their own profile (enforced at service level if desired)."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User updated",
                    content = @Content(schema = @Schema(implementation = UserResponseDto.class))),
            @ApiResponse(responseCode = "400", description = "Validation error"),
            @ApiResponse(responseCode = "401", description = "Unauthorised"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "409", description = "Email already in use")
    })
    public ResponseEntity<UserResponseDto> updateUser(
            @Parameter(description = "User ID", required = true) @PathVariable Long id,
            @Valid @RequestBody UpdateUserDto request
    ) {
        log.info("PUT /api/users/{}", id);
        return ResponseEntity.ok(userService.updateUser(id, request));
    }

    // ------------------------------------------------------------------
    // DELETE /api/users/{id}
    // ------------------------------------------------------------------

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @Operation(
            summary = "Delete a user (ADMIN only)",
            description = "Permanently deletes the user with the given ID. Requires ROLE_ADMIN."
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "User deleted"),
            @ApiResponse(responseCode = "401", description = "Unauthorised"),
            @ApiResponse(responseCode = "403", description = "Forbidden — ROLE_ADMIN required"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "User ID", required = true) @PathVariable Long id
    ) {
        log.info("DELETE /api/users/{}", id);
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
