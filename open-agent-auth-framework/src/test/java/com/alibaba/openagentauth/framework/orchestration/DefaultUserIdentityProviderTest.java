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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link DefaultUserIdentityProvider}.
 * <p>
 * This test class validates the User IDP orchestration implementation,
 * including authentication delegation and token issuance.
 * </p>
 */
@DisplayName("DefaultUserIdentityProvider Tests")
@ExtendWith(MockitoExtension.class)
class DefaultUserIdentityProviderTest {

    private DefaultUserIdentityProvider userIdentityProvider;
    private AuthenticationProvider mockAuthenticationProvider;
    private OAuth2TokenServer mockTokenServer;

    private static final String USER_ID = "user-123";
    private static final String TOKEN_VALUE = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";
    private static final String CLIENT_ID = "client-123";
    private static final String ISSUER = "https://issuer.example.com";

    @BeforeEach
    void setUp() {
        mockAuthenticationProvider = mock(AuthenticationProvider.class);
        mockTokenServer = mock(OAuth2TokenServer.class);
        userIdentityProvider = new DefaultUserIdentityProvider(mockAuthenticationProvider, mockTokenServer);
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create provider with valid parameters")
        void shouldCreateProviderWithValidParameters() {
            // Act
            DefaultUserIdentityProvider provider = new DefaultUserIdentityProvider(
                    mockAuthenticationProvider, mockTokenServer);

            // Assert
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when authentication provider is null")
        void shouldThrowExceptionWhenAuthenticationProviderIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultUserIdentityProvider(null, mockTokenServer))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AuthenticationProvider cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when token server is null")
        void shouldThrowExceptionWhenTokenServerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultUserIdentityProvider(mockAuthenticationProvider, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("OAuth2TokenServer cannot be null");
        }
    }

    @Nested
    @DisplayName("authenticate()")
    class Authenticate {

        @Test
        @DisplayName("Should successfully authenticate user")
        void shouldSuccessfullyAuthenticateUser() throws AuthenticationException {
            // Arrange
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid profile email")
                    .state("state-123")
                    .build();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getTokenValue()).thenReturn(TOKEN_VALUE);
            when(idToken.getClaims()).thenReturn(claims);

            when(mockAuthenticationProvider.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(idToken);

            // Act
            AuthenticationResponse response = userIdentityProvider.authenticate(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getIdToken()).isEqualTo(TOKEN_VALUE);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(3600);

            verify(mockAuthenticationProvider, times(1)).authenticate(request);
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> userIdentityProvider.authenticate(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authentication request cannot be null");
        }

        @Test
        @DisplayName("Should propagate authentication exception")
        void shouldPropagateAuthenticationException() throws AuthenticationException {
            // Arrange
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .state("state-123")
                    .build();

            when(mockAuthenticationProvider.authenticate(any(AuthenticationRequest.class)))
                    .thenThrow(new AuthenticationException("Invalid credentials"));

            // Act & Assert
            assertThatThrownBy(() -> userIdentityProvider.authenticate(request))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Invalid credentials");
        }

        @Test
        @DisplayName("Should calculate expires in as 0 when claims are missing")
        void shouldCalculateExpiresInAsZeroWhenClaimsAreMissing() throws AuthenticationException {
            // Arrange
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .state("state-123")
                    .build();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub(USER_ID)
                    .iss(ISSUER)
                    .aud(CLIENT_ID)
                    .iat(Instant.now())
                    .exp(Instant.now())
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getTokenValue()).thenReturn(TOKEN_VALUE);
            when(idToken.getClaims()).thenReturn(claims);

            when(mockAuthenticationProvider.authenticate(any(AuthenticationRequest.class)))
                    .thenReturn(idToken);

            // Act
            AuthenticationResponse response = userIdentityProvider.authenticate(request);

            // Assert
            assertThat(response.getExpiresIn()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("issueToken()")
    class IssueToken {

        @Test
        @DisplayName("Should successfully issue token")
        void shouldSuccessfullyIssueToken() throws Exception {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code("auth-code-123")
                    .redirectUri("https://example.com/callback")
                    .clientId(CLIENT_ID)
                    .build();

            TokenResponse expectedResponse = TokenResponse.builder()
                    .accessToken(TOKEN_VALUE)
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .scope("openid profile")
                    .build();

            when(mockTokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(expectedResponse);

            // Act
            TokenResponse response = userIdentityProvider.issueToken(request, CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(TOKEN_VALUE);
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(3600L);

            verify(mockTokenServer, times(1)).issueToken(request, CLIENT_ID);
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when token server throws exception")
        void shouldThrowFrameworkOAuth2TokenExceptionWhenTokenServerThrowsException() throws Exception {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code("auth-code-123")
                    .redirectUri("https://example.com/callback")
                    .clientId(CLIENT_ID)
                    .build();

            when(mockTokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenThrow(new RuntimeException("Invalid authorization code"));

            // Act & Assert
            assertThatThrownBy(() -> userIdentityProvider.issueToken(request, CLIENT_ID))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Failed to issue token");
        }
    }
}
