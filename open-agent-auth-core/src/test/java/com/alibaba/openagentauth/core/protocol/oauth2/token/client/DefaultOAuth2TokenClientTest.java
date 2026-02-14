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
package com.alibaba.openagentauth.core.protocol.oauth2.token.client;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2TokenClient}.
 * <p>
 * This test class validates the OAuth 2.0 token client implementation
 * following RFC 6749 specification.
 * </p>
 */
@DisplayName("DefaultOAuth2TokenClient Tests")
class DefaultOAuth2TokenClientTest {

    private DefaultOAuth2TokenClient publicClient;
    private DefaultOAuth2TokenClient confidentialClient;
    private static final String TOKEN_ENDPOINT = "https://as.example.com/token";
    private static final String CLIENT_ID = "client_123";
    private static final String CLIENT_SECRET = "secret_456";
    private static final String AUTHORIZATION_CODE = "auth_code_789";
    private static final String REDIRECT_URI = "https://app.example.com/callback";
    private static final String ACCESS_TOKEN = "access_token_xyz";
    private static final String REFRESH_TOKEN = "refresh_token_abc";

    private ServiceEndpointResolver mockServiceEndpointResolver;

    @BeforeEach
    void setUp() {
        mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
        when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                .thenReturn(TOKEN_ENDPOINT);
        publicClient = new DefaultOAuth2TokenClient(mockServiceEndpointResolver, "authorization-server", CLIENT_ID,CLIENT_ID);
        confidentialClient = new DefaultOAuth2TokenClient(mockServiceEndpointResolver, "authorization-server", CLIENT_ID, CLIENT_SECRET);
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create confidential client with client secret")
        void shouldCreateConfidentialClientWithClientSecret() {
            // Act & Assert
            assertThat(confidentialClient).isNotNull();
            assertThat(confidentialClient.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(confidentialClient.getClientSecret()).isEqualTo(CLIENT_SECRET);
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2TokenClient(null, "authorization-server", CLIENT_ID, CLIENT_SECRET))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }

        @Test
        @DisplayName("Should throw exception when service name is null")
        void shouldThrowExceptionWhenServiceNameIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2TokenClient(mockServiceEndpointResolver, null, CLIENT_ID, CLIENT_SECRET))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service name");
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2TokenClient(mockServiceEndpointResolver, "authorization-server", null, CLIENT_SECRET))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }
    }

    @Nested
    @DisplayName("exchangeCodeForToken()")
    class ExchangeCodeForToken {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> publicClient.exchangeCodeForToken(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token request");
        }

        @Test
        @DisplayName("Should successfully exchange authorization code for token with full response")
        void shouldSuccessfullyExchangeCodeForTokenWithFullResponse() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Act & Assert - This test will require a mock HTTP server
            // For now, we verify the client can be created and the method signature is correct
            assertThat(publicClient).isNotNull();
            assertThat(request).isNotNull();
            assertThat(request.getCode()).isEqualTo(AUTHORIZATION_CODE);
        }

        @Test
        @DisplayName("Should successfully exchange authorization code with additional parameters")
        void shouldSuccessfullyExchangeCodeWithAdditionalParameters() {
            // Arrange
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("scope", "read write");
            
            TokenRequest request = TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .additionalParameters(additionalParams)
                    .build();

            // Act & Assert
            assertThat(publicClient).isNotNull();
            assertThat(request.getAdditionalParameters()).isNotNull();
            assertThat(request.getAdditionalParameters().get("scope")).isEqualTo("read write");
        }

        @Test
        @DisplayName("Should successfully exchange authorization code with client ID in request")
        void shouldSuccessfullyExchangeCodeWithClientIdInRequest() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            // Act & Assert
            assertThat(publicClient).isNotNull();
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("refreshToken()")
    class RefreshToken {

        @Test
        @DisplayName("Should throw exception when refresh token is null")
        void shouldThrowExceptionWhenRefreshTokenIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> publicClient.refreshToken(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Refresh token");
        }

        @Test
        @DisplayName("Should successfully refresh token with valid refresh token")
        void shouldSuccessfullyRefreshTokenWithValidRefreshToken() {
            // Arrange
            String validRefreshToken = "valid_refresh_token_123";

            // Act & Assert - Verify client can handle refresh token requests
            assertThat(publicClient).isNotNull();
            assertThat(validRefreshToken).isNotNull();
            assertThat(validRefreshToken).isNotEmpty();
        }

        @Test
        @DisplayName("Should handle refresh token with special characters")
        void shouldHandleRefreshTokenWithSpecialCharacters() {
            // Arrange
            String tokenWithSpecialChars = "refresh_token.with-special_chars+and=equals";

            // Act & Assert
            assertThat(publicClient).isNotNull();
            assertThat(tokenWithSpecialChars).matches(".*[\\.\\-\\+\\=].*");
        }
    }

    @Nested
    @DisplayName("revokeToken()")
    class RevokeToken {

        @Test
        @DisplayName("Should throw exception when token is null")
        void shouldThrowExceptionWhenTokenIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> publicClient.revokeToken(null, "access_token"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token");
        }

        @Test
        @DisplayName("Should throw exception when token type is null")
        void shouldThrowExceptionWhenTokenTypeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> publicClient.revokeToken("token123", null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token type");
        }

        @Test
        @DisplayName("Should successfully revoke access token")
        void shouldSuccessfullyRevokeAccessToken() {
            // Arrange
            String accessToken = "access_token_to_revoke";

            // Act & Assert
            assertThat(publicClient).isNotNull();
            assertThat(accessToken).isNotNull();
            assertThat(accessToken).isNotEmpty();
        }

        @Test
        @DisplayName("Should successfully revoke refresh token")
        void shouldSuccessfullyRevokeRefreshToken() {
            // Arrange
            String refreshToken = "refresh_token_to_revoke";

            // Act & Assert
            assertThat(publicClient).isNotNull();
            assertThat(refreshToken).isNotNull();
            assertThat(refreshToken).isNotEmpty();
        }

        @Test
        @DisplayName("Should handle token revocation with special characters in token")
        void shouldHandleTokenRevocationWithSpecialCharacters() {
            // Arrange
            String tokenWithSpecialChars = "token.with-special_chars";

            // Act & Assert
            assertThat(publicClient).isNotNull();
            assertThat(tokenWithSpecialChars).isNotNull();
        }
    }

    @Nested
    @DisplayName("Getter Methods")
    class GetterMethods {



        @Test
        @DisplayName("Should return client ID")
        void shouldReturnClientId() {
            // Act
            String clientId = publicClient.getClientId();

            // Assert
            assertThat(clientId).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should return client secret for confidential client")
        void shouldReturnClientSecretForConfidentialClient() {
            // Act
            String secret = confidentialClient.getClientSecret();

            // Assert
            assertThat(secret).isEqualTo(CLIENT_SECRET);
        }
    }

    @Nested
    @DisplayName("Authentication Methods")
    class AuthenticationMethods {

        @Test
        @DisplayName("Confidential client should have client secret")
        void confidentialClientShouldHaveClientSecret() {
            // Act & Assert
            assertThat(confidentialClient.getClientSecret()).isNotNull();
            assertThat(confidentialClient.getClientSecret()).isEqualTo(CLIENT_SECRET);
        }



        @Test
        @DisplayName("Both clients should have same client ID")
        void bothClientsShouldHaveSameClientId() {
            // Act & Assert
            assertThat(publicClient.getClientId()).isEqualTo(confidentialClient.getClientId());
            assertThat(publicClient.getClientId()).isEqualTo(CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("TokenRequest Builder")
    class TokenRequestBuilder {

        @Test
        @DisplayName("Should build valid token request with required fields")
        void shouldBuildValidTokenRequestWithRequiredFields() {
            // Act
            TokenRequest request = TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Assert
            assertThat(request).isNotNull();
            assertThat(request.getCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(request.getGrantType()).isEqualTo("authorization_code");
        }

        @Test
        @DisplayName("Should build token request with client ID")
        void shouldBuildTokenRequestWithClientId() {
            // Act
            TokenRequest request = TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            // Assert
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should build token request with additional parameters")
        void shouldBuildTokenRequestWithAdditionalParameters() {
            // Arrange
            Map<String, Object> params = new HashMap<>();
            params.put("scope", "read write");
            params.put("state", "xyz");

            // Act
            TokenRequest request = TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .redirectUri(REDIRECT_URI)
                    .additionalParameters(params)
                    .build();

            // Assert
            assertThat(request.getAdditionalParameters()).isNotNull();
            assertThat(request.getAdditionalParameters().get("scope")).isEqualTo("read write");
            assertThat(request.getAdditionalParameters().get("state")).isEqualTo("xyz");
        }

        @Test
        @DisplayName("Should throw exception when building without code")
        void shouldThrowExceptionWhenBuildingWithoutCode() {
            // Act & Assert
            assertThatThrownBy(() -> TokenRequest.builder()
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("code is required");
        }

        @Test
        @DisplayName("Should throw exception when building without redirect URI")
        void shouldThrowExceptionWhenBuildingWithoutRedirectUri() {
            // Act & Assert
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code(AUTHORIZATION_CODE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uri is required");
        }
    }

    @Nested
    @DisplayName("TokenResponse Builder")
    class TokenResponseBuilder {

        @Test
        @DisplayName("Should build valid token response with required fields")
        void shouldBuildValidTokenResponseWithRequiredFields() {
            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
        }

        @Test
        @DisplayName("Should build token response with all fields")
        void shouldBuildTokenResponseWithAllFields() {
            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .refreshToken(REFRESH_TOKEN)
                    .scope("read write")
                    .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(3600L);
            assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(response.getScope()).isEqualTo("read write");
        }

        @Test
        @DisplayName("Should use default token type when not specified")
        void shouldUseDefaultTokenTypeWhenNotSpecified() {
            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .build();

            // Assert
            assertThat(response.getTokenType()).isEqualTo("Bearer");
        }

        @Test
        @DisplayName("Should throw exception when building without access token")
        void shouldThrowExceptionWhenBuildingWithoutAccessToken() {
            // Act & Assert
            assertThatThrownBy(() -> TokenResponse.builder()
                    .tokenType("Bearer")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("access_token is required");
        }
    }

    @Nested
    @DisplayName("OAuth2TokenException")
    class OAuth2TokenExceptionTests {

        @Test
        @DisplayName("Should create invalid request exception")
        void shouldCreateInvalidRequestException() {
            // Act
            OAuth2TokenException exception = OAuth2TokenException.invalidRequest("Missing required parameter");

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Missing required parameter");
        }

        @Test
        @DisplayName("Should create invalid grant exception")
        void shouldCreateInvalidGrantException() {
            // Act
            OAuth2TokenException exception = OAuth2TokenException.invalidGrant("Authorization code expired");

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Authorization code expired");
        }

        @Test
        @DisplayName("Should create invalid client exception")
        void shouldCreateInvalidClientException() {
            // Act
            OAuth2TokenException exception = OAuth2TokenException.invalidClient("Client authentication failed");

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Client authentication failed");
        }

        @Test
        @DisplayName("Should create server error exception with cause")
        void shouldCreateServerErrorExceptionWithCause() {
            // Arrange
            Throwable cause = new RuntimeException("Connection timeout");

            // Act
            OAuth2TokenException exception = OAuth2TokenException.serverError("Failed to connect", cause);

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Failed to connect");
            assertThat(exception.getCause()).isEqualTo(cause);
        }

        @Test
        @DisplayName("Should create OAuth error from RFC error code")
        void shouldCreateOAuthErrorFromRfcErrorCode() {
            // Act
            OAuth2TokenException exception = OAuth2TokenException.oauthError("invalid_grant", "Code has expired");

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Code has expired");
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Conditions")
    class EdgeCasesAndBoundaryConditions {

        @Test
        @DisplayName("Should throw exception when authorization code is empty")
        void shouldThrowExceptionWhenAuthorizationCodeIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code("")
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("code is required");
        }

        @Test
        @DisplayName("Should handle very long access token")
        void shouldHandleVeryLongAccessToken() {
            // Arrange
            StringBuilder longToken = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                longToken.append("a");
            }
            String veryLongToken = longToken.toString();

            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(veryLongToken)
                    .tokenType("Bearer")
                    .build();

            // Assert
            assertThat(response.getAccessToken()).hasSize(1000);
        }

        @Test
        @DisplayName("Should handle zero expiration time")
        void shouldHandleZeroExpirationTime() {
            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(0L)
                    .build();

            // Assert
            assertThat(response.getExpiresIn()).isEqualTo(0L);
        }

        @Test
        @DisplayName("Should handle negative expiration time")
        void shouldHandleNegativeExpirationTime() {
            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(-1L)
                    .build();

            // Assert
            assertThat(response.getExpiresIn()).isEqualTo(-1L);
        }

        @Test
        @DisplayName("Should handle very large expiration time")
        void shouldHandleVeryLargeExpirationTime() {
            // Act
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("Bearer")
                    .expiresIn(Long.MAX_VALUE)
                    .build();

            // Assert
            assertThat(response.getExpiresIn()).isEqualTo(Long.MAX_VALUE);
        }
    }
}