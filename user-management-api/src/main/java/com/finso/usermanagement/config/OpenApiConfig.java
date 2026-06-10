package com.finso.usermanagement.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "User Management API",
                version = "1.0.0",
                description = "Production-quality REST API for user management with JWT authentication. "
                        + "Register or login via /api/auth endpoints to obtain a Bearer token, "
                        + "then use the Authorize button above to unlock the protected endpoints.",
                contact = @Contact(
                        name = "Finso",
                        email = "support@finso.com"
                ),
                license = @License(
                        name = "MIT License",
                        url = "https://opensource.org/licenses/MIT"
                )
        ),
        servers = {
                @Server(url = "http://localhost:8080", description = "Local development server"),
                @Server(url = "https://api.finso.com", description = "Production server")
        },
        security = @SecurityRequirement(name = "bearerAuth")
)
@SecurityScheme(
        name = "bearerAuth",
        description = "JWT Bearer token authentication. Obtain a token via POST /api/auth/login.",
        scheme = "bearer",
        type = SecuritySchemeType.HTTP,
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER
)
public class OpenApiConfig {
    // All configuration is handled via annotations above.
}
