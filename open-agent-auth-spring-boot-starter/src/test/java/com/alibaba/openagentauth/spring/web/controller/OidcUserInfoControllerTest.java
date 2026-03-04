/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OidcUserInfoController}.
 * <p>
 * This test class verifies the OIDC UserInfo endpoint functionality with
 * Bearer Token authentication per OIDC Core 1.0 Section 5.3 and RFC 6750.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OidcUserInfoController Tests")
class OidcUserInfoControllerTest {

    private static final String SUBJECT = "user123";
    private static final String NAME = "Test User";
    private static final String EMAIL = "test@example.com";
    private static final String KEY_ID = "test-id-token-signing-key";
    private static final String ISSUER = "http://localhost:8080";

    @Mock
    private UserRegistry userRegistry;

    private KeyManager keyManager;

    @Mock
    private HttpServletRequest request;

    private OidcUserInfoController controller;

    private DefaultIdTokenGenerator idTokenGenerator;

    @BeforeEach
    void setUp() throws KeyManagementException, JOSEException {
        // Use a real KeyManager with InMemoryKeyStore for actual key generation and verification
        keyManager = new DefaultKeyManager(new InMemoryKeyStore());
        keyManager.generateKeyPair(KeyAlgorithm.RS256, KEY_ID);
        Object signingJwk = keyManager.getSigningJWK(KEY_ID);

        // Create a real IdTokenGenerator for generating valid JWTs
        idTokenGenerator = new DefaultIdTokenGenerator(ISSUER, "RS256", signingJwk);

        // Mock OpenAgentAuthProperties to return the key ID
        OpenAgentAuthProperties properties = mock(OpenAgentAuthProperties.class);
        KeyDefinitionProperties keyDefinitionProperties = mock(KeyDefinitionProperties.class);
        when(keyDefinitionProperties.getKeyId()).thenReturn(KEY_ID);
        when(properties.getKeyDefinition("id-token-signing")).thenReturn(keyDefinitionProperties);

        // Create the controller under test
        controller = new OidcUserInfoController(userRegistry, keyManager, properties);

        // Default mock setup for user registry
        lenient().when(userRegistry.getName(SUBJECT)).thenReturn(NAME);
        lenient().when(userRegistry.getEmail(SUBJECT)).thenReturn(EMAIL);
    }

    /**
     * Generates a valid signed JWT access token for testing.
     */
    private String generateValidAccessToken(String subject) {
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(subject)
                .aud("test-client")
                .iat(Instant.now())
                .exp(Instant.now().plusSeconds(3600))
                .build();
        IdToken idToken = idTokenGenerator.generate(claims);
        return idToken.getTokenValue();
    }

    /**
     * Generates an expired signed JWT access token for testing.
     */
    private String generateExpiredAccessToken(String subject) {
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(subject)
                .aud("test-client")
                .iat(Instant.now().minusSeconds(7200))
                .exp(Instant.now().minusSeconds(3600))
                .build();
        IdToken idToken = idTokenGenerator.generate(claims);
        return idToken.getTokenValue();
    }

    /**
     * Generates a valid signed JWT access token with scope claim for testing.
     */
    private String generateAccessTokenWithScope(String subject, String scope) {
        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("scope", scope);
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(subject)
                .aud("test-client")
                .iat(Instant.now())
                .exp(Instant.now().plusSeconds(3600))
                .additionalClaims(additionalClaims)
                .build();
        IdToken idToken = idTokenGenerator.generate(claims);
        return idToken.getTokenValue();
    }

    @Nested
    @DisplayName("GET /oauth2/userinfo - Success Scenarios")
    class SuccessScenarios {

        @Test
        @DisplayName("Should return user info when valid Bearer Token is provided")
        void shouldReturnUserInfoWhenValidBearerTokenProvided() {
            // Arrange
            String accessToken = generateValidAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("sub", SUBJECT);
            assertThat(response.getBody()).containsEntry("name", NAME);
            assertThat(response.getBody()).containsEntry("email", EMAIL);
            assertThat(response.getBody()).containsEntry("preferred_username", SUBJECT);
        }

        @Test
        @DisplayName("Should return subject as name when name is null")
        void shouldReturnSubjectAsNameWhenNameIsNull() {
            // Arrange
            String accessToken = generateValidAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);
            when(userRegistry.getName(SUBJECT)).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("name", SUBJECT);
        }

        @Test
        @DisplayName("Should include all standard OIDC claims")
        void shouldIncludeAllStandardOidcClaims() {
            // Arrange
            String accessToken = generateValidAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            Map<String, Object> userInfo = response.getBody();
            assertThat(userInfo).containsKeys("sub", "name", "email", "preferred_username");
        }

        @Test
        @DisplayName("Should handle null email gracefully")
        void shouldHandleNullEmailGracefully() {
            // Arrange
            String accessToken = generateValidAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);
            when(userRegistry.getEmail(SUBJECT)).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsEntry("email", null);
        }

        @Test
        @DisplayName("Should return only profile claims when scope is 'openid profile'")
        void shouldReturnOnlyProfileClaimsWhenScopeIsProfile() {
            String accessToken = generateAccessTokenWithScope(SUBJECT, "openid profile");
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);

            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsKey("sub");
            assertThat(response.getBody()).containsKey("name");
            assertThat(response.getBody()).containsKey("preferred_username");
            assertThat(response.getBody()).doesNotContainKey("email");
        }

        @Test
        @DisplayName("Should return only email claim when scope is 'openid email'")
        void shouldReturnOnlyEmailClaimWhenScopeIsEmail() {
            String accessToken = generateAccessTokenWithScope(SUBJECT, "openid email");
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);

            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsKey("sub");
            assertThat(response.getBody()).containsKey("email");
            assertThat(response.getBody()).doesNotContainKey("name");
            assertThat(response.getBody()).doesNotContainKey("preferred_username");
        }

        @Test
        @DisplayName("Should return all claims when scope includes profile and email")
        void shouldReturnAllClaimsWhenScopeIncludesProfileAndEmail() {
            String accessToken = generateAccessTokenWithScope(SUBJECT, "openid profile email");
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);

            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsKeys("sub", "name", "email", "preferred_username");
        }

        @Test
        @DisplayName("Should return all claims when no scope claim in token (backward compatibility)")
        void shouldReturnAllClaimsWhenNoScopeInToken() {
            String accessToken = generateValidAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);

            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsKeys("sub", "name", "email", "preferred_username");
        }
    }

    @Nested
    @DisplayName("GET /oauth2/userinfo - Bearer Token Authentication Errors")
    class BearerTokenAuthenticationErrors {

        @Test
        @DisplayName("Should return 401 when Authorization header is missing")
        void shouldReturn401WhenAuthorizationHeaderMissing() {
            // Arrange
            when(request.getHeader("Authorization")).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", "invalid_request");
            assertThat(response.getHeaders().getFirst("WWW-Authenticate")).contains("Bearer");
        }

        @Test
        @DisplayName("Should return 401 when Authorization header does not start with Bearer")
        void shouldReturn401WhenNotBearerScheme() {
            // Arrange
            when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).containsEntry("error", "invalid_request");
        }

        @Test
        @DisplayName("Should return 401 when Bearer token is empty")
        void shouldReturn401WhenBearerTokenEmpty() {
            // Arrange
            when(request.getHeader("Authorization")).thenReturn("Bearer ");

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).containsEntry("error", "invalid_request");
        }

        @Test
        @DisplayName("Should return 401 when token is not a valid JWT")
        void shouldReturn401WhenTokenIsNotValidJwt() {
            // Arrange
            when(request.getHeader("Authorization")).thenReturn("Bearer not-a-valid-jwt");

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).containsEntry("error", "invalid_token");
        }

        @Test
        @DisplayName("Should return 401 when token has expired")
        void shouldReturn401WhenTokenExpired() {
            // Arrange
            String expiredToken = generateExpiredAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + expiredToken);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).containsEntry("error", "invalid_token");
        }

        @Test
        @DisplayName("Should include WWW-Authenticate header in 401 responses per RFC 6750")
        void shouldIncludeWwwAuthenticateHeader() {
            // Arrange
            when(request.getHeader("Authorization")).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            String wwwAuthenticate = response.getHeaders().getFirst("WWW-Authenticate");
            assertThat(wwwAuthenticate).isNotNull();
            assertThat(wwwAuthenticate).startsWith("Bearer");
            assertThat(wwwAuthenticate).contains("error=");
        }
    }

    @Nested
    @DisplayName("GET /oauth2/userinfo - Server Error Handling")
    class ServerErrorHandling {

        @Test
        @DisplayName("Should return 500 when user registry throws exception")
        void shouldReturn500WhenUserRegistryThrowsException() {
            // Arrange
            String accessToken = generateValidAccessToken(SUBJECT);
            when(request.getHeader("Authorization")).thenReturn("Bearer " + accessToken);
            when(userRegistry.getName(SUBJECT)).thenThrow(new RuntimeException("Registry error"));

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", "server_error");
            assertThat(response.getBody()).containsEntry("error_description", "Internal server error");
        }
    }
}