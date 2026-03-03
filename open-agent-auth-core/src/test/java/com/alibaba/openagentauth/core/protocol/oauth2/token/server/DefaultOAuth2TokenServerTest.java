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
package com.alibaba.openagentauth.core.protocol.oauth2.token.server;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2TokenServer}.
 * <p>
 * This test class validates the OAuth 2.0 token issuance logic according to RFC 6749.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DefaultOAuth2TokenServer Tests")
class DefaultOAuth2TokenServerTest {

    @Mock
    private OAuth2AuthorizationCodeStorage codeStorage;

    @Mock
    private TokenGenerator tokenGenerator;

    private DefaultOAuth2TokenServer tokenServer;

    private static final String TEST_CLIENT_ID = "test-client-123";
    private static final String TEST_CODE = "auth_code_xyz";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_ACCESS_TOKEN = "access_token_abc123";
    private static final String TEST_SUBJECT = "user_123";
    private static final String TEST_SCOPE = "read write";
    private static final long DEFAULT_EXPIRATION_SECONDS = 3600L;

    @BeforeEach
    void setUp() {
        tokenServer = new DefaultOAuth2TokenServer(codeStorage, tokenGenerator);
        
        // Default mock behavior for token generator (lenient to avoid unnecessary stubbing warnings)
        lenient().when(tokenGenerator.getExpirationSeconds()).thenReturn(DEFAULT_EXPIRATION_SECONDS);
    }

    @Nested
    @DisplayName("issueToken() - Happy Path")
    class IssueTokenHappyPath {

        @Test
        @DisplayName("Should successfully issue token with valid authorization code")
        void shouldSuccessfullyIssueTokenWithValidAuthorizationCode() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);
            when(tokenGenerator.generateToken(authCode, request)).thenReturn(TEST_ACCESS_TOKEN);

            // Act
            TokenResponse response = tokenServer.issueToken(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(DEFAULT_EXPIRATION_SECONDS);
            assertThat(response.getScope()).isEqualTo(TEST_SCOPE);
            assertThat(response.getIdToken()).isNull();

            // Verify interactions
            verify(codeStorage).retrieve(TEST_CODE);
            verify(tokenGenerator).generateToken(authCode, request);
            verify(codeStorage).consume(TEST_CODE);
        }

        @Test
        @DisplayName("Should include id_token in response when scope contains openid")
        void shouldIncludeIdTokenInResponseWhenScopeContainsOpenid() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCodeWithOpenIdScope();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);
            when(tokenGenerator.generateToken(authCode, request)).thenReturn(TEST_ACCESS_TOKEN);

            // Act
            TokenResponse response = tokenServer.issueToken(request, TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getIdToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getScope()).isEqualTo("openid profile");
        }

        @Test
        @DisplayName("Should mark authorization code as used after successful token issuance")
        void shouldMarkAuthorizationCodeAsUsedAfterSuccessfulTokenIssuance() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);
            when(tokenGenerator.generateToken(authCode, request)).thenReturn(TEST_ACCESS_TOKEN);

            // Act
            tokenServer.issueToken(request, TEST_CLIENT_ID);

            // Assert - Verify consume was called
            verify(codeStorage).consume(TEST_CODE);
        }
    }

    @Nested
    @DisplayName("issueToken() - Validation Errors")
    class IssueTokenValidationErrors {

        @Test
        @DisplayName("Should throw OAuth2TokenException when token request is null")
        void shouldThrowExceptionWhenTokenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(null, TEST_CLIENT_ID))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "server_error")
                    .hasMessageContaining("Internal server error during token issuance");
        }

        @Test
        @DisplayName("Should throw OAuth2TokenException when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, null))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "server_error")
                    .hasMessageContaining("Internal server error during token issuance");
        }

        @Test
        @DisplayName("Should throw server_error exception when code is missing due to builder validation")
        void shouldThrowServerErrorExceptionWhenCodeIsMissing() {
            // Act & Assert - TokenRequest.Builder will throw IllegalStateException before reaching the server
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code(null)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("code is required");
        }

        @Test
        @DisplayName("Should throw server_error exception when code is empty due to builder validation")
        void shouldThrowServerErrorExceptionWhenCodeIsEmpty() {
            // Act & Assert - TokenRequest.Builder will throw IllegalStateException before reaching the server
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code("")
                    .redirectUri(TEST_REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("code is required");
        }

        @Test
        @DisplayName("Should throw server_error exception when redirect URI is missing due to builder validation")
        void shouldThrowServerErrorExceptionWhenRedirectUriIsMissing() {
            // Act & Assert - TokenRequest.Builder will throw IllegalStateException before reaching the server
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uri is required");
        }
    }

    @Nested
    @DisplayName("issueToken() - Authorization Code Validation")
    class IssueTokenAuthorizationCodeValidation {

        @Test
        @DisplayName("Should throw invalid_grant exception when authorization code not found")
        void shouldThrowInvalidGrantExceptionWhenAuthorizationCodeNotFound() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            when(codeStorage.retrieve(TEST_CODE)).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, TEST_CLIENT_ID))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("Authorization code not found");
        }

        @Test
        @DisplayName("Should throw invalid_grant exception when client ID mismatch")
        void shouldThrowInvalidGrantExceptionWhenClientIdMismatch() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, "different-client-id"))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("bound to a different client");
        }

        @Test
        @DisplayName("Should throw invalid_grant exception when redirect URI mismatch")
        void shouldThrowInvalidGrantExceptionWhenRedirectUriMismatch() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri("https://different.com/callback")
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, TEST_CLIENT_ID))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("Redirect URI does not match");
        }

        @Test
        @DisplayName("Should throw invalid_grant exception when authorization code is expired")
        void shouldThrowInvalidGrantExceptionWhenAuthorizationCodeIsExpired() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createExpiredAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, TEST_CLIENT_ID))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("Authorization code has expired");
        }

        @Test
        @DisplayName("Should throw invalid_grant exception when authorization code is already used")
        void shouldThrowInvalidGrantExceptionWhenAuthorizationCodeIsAlreadyUsed() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createUsedAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, TEST_CLIENT_ID))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant")
                    .hasMessageContaining("Authorization code has already been used");
        }
    }

    @Nested
    @DisplayName("issueToken() - Token Generation Errors")
    class IssueTokenTokenGenerationErrors {

        @Test
        @DisplayName("Should throw server_error exception when token generation fails")
        void shouldThrowServerErrorExceptionWhenTokenGenerationFails() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);
            when(tokenGenerator.generateToken(authCode, request))
                    .thenThrow(new RuntimeException("Token generation failed"));

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.issueToken(request, TEST_CLIENT_ID))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "server_error")
                    .hasMessageContaining("Internal server error during token issuance");
        }
    }

    @Nested
    @DisplayName("validateTokenRequest()")
    class ValidateTokenRequest {

        @Test
        @DisplayName("Should successfully validate valid token request")
        void shouldSuccessfullyValidateValidTokenRequest() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            // Act & Assert - Should not throw any exception
            tokenServer.validateTokenRequest(request, TEST_CLIENT_ID);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> tokenServer.validateTokenRequest(null, TEST_CLIENT_ID))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token request");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> tokenServer.validateTokenRequest(request, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }
    }

    @Nested
    @DisplayName("validateAndRetrieveAuthorizationCode()")
    class ValidateAndRetrieveAuthorizationCode {

        @Test
        @DisplayName("Should successfully retrieve and validate authorization code")
        void shouldSuccessfullyRetrieveAndValidateAuthorizationCode() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(TEST_CODE)
                    .redirectUri(TEST_REDIRECT_URI)
                    .build();

            AuthorizationCode authCode = createValidAuthorizationCode();
            when(codeStorage.retrieve(TEST_CODE)).thenReturn(authCode);

            // Act
            AuthorizationCode result = tokenServer.validateAndRetrieveAuthorizationCode(request, TEST_CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(TEST_CODE);
            assertThat(result.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(result.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        }
    }

    @Nested
    @DisplayName("buildTokenResponse()")
    class BuildTokenResponse {

        @Test
        @DisplayName("Should build token response with all fields")
        void shouldBuildTokenResponseWithAllFields() {
            // Act
            TokenResponse response = tokenServer.buildTokenResponse(
                    TEST_ACCESS_TOKEN,
                    DEFAULT_EXPIRATION_SECONDS,
                    TEST_SCOPE
            );

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(DEFAULT_EXPIRATION_SECONDS);
            assertThat(response.getScope()).isEqualTo(TEST_SCOPE);
        }

        @Test
        @DisplayName("Should build token response with id_token when scope contains openid")
        void shouldBuildTokenResponseWithIdTokenWhenScopeContainsOpenid() {
            // Act
            TokenResponse response = tokenServer.buildTokenResponse(
                    TEST_ACCESS_TOKEN,
                    DEFAULT_EXPIRATION_SECONDS,
                    "openid profile",
                    TEST_ACCESS_TOKEN
            );

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getIdToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getScope()).isEqualTo("openid profile");
        }

        @Test
        @DisplayName("Should build token response without id_token when idToken parameter is null")
        void shouldBuildTokenResponseWithoutIdTokenWhenIdTokenParameterIsNull() {
            // Act
            TokenResponse response = tokenServer.buildTokenResponse(
                    TEST_ACCESS_TOKEN,
                    DEFAULT_EXPIRATION_SECONDS,
                    TEST_SCOPE,
                    null
            );

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getIdToken()).isNull();
        }

        @Test
        @DisplayName("Should build token response with null scope")
        void shouldBuildTokenResponseWithNullScope() {
            // Act
            TokenResponse response = tokenServer.buildTokenResponse(
                    TEST_ACCESS_TOKEN,
                    DEFAULT_EXPIRATION_SECONDS,
                    null
            );

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TEST_ACCESS_TOKEN);
            assertThat(response.getScope()).isNull();
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return code storage")
        void shouldReturnCodeStorage() {
            // Act
            OAuth2AuthorizationCodeStorage storage = tokenServer.getCodeStorage();

            // Assert
            assertThat(storage).isSameAs(codeStorage);
        }

        @Test
        @DisplayName("Should return token generator")
        void shouldReturnTokenGenerator() {
            // Act
            TokenGenerator generator = tokenServer.getTokenGenerator();

            // Assert
            assertThat(generator).isSameAs(tokenGenerator);
        }
    }

    // Helper methods

    private AuthorizationCode createValidAuthorizationCode() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(TEST_CODE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope(TEST_SCOPE)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                .used(false)
                .build();
    }

    private AuthorizationCode createValidAuthorizationCodeWithOpenIdScope() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(TEST_CODE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope("openid profile")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                .used(false)
                .build();
    }

    private AuthorizationCode createExpiredAuthorizationCode() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(TEST_CODE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope(TEST_SCOPE)
                .issuedAt(now.minusSeconds(DEFAULT_EXPIRATION_SECONDS * 2))
                .expiresAt(now.minusSeconds(100))
                .used(false)
                .build();
    }

    private AuthorizationCode createUsedAuthorizationCode() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code(TEST_CODE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .subject(TEST_SUBJECT)
                .scope(TEST_SCOPE)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(DEFAULT_EXPIRATION_SECONDS))
                .used(true)
                .build();
    }
}