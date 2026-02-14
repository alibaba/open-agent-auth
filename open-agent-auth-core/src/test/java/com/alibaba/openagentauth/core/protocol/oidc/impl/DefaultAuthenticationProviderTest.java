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
package com.alibaba.openagentauth.core.protocol.oidc.impl;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.strategy.AuthenticationMethod;
import com.alibaba.openagentauth.core.protocol.oidc.strategy.AuthenticationResult;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultAuthenticationProvider}.
 * <p>
 * This test class validates the authentication provider implementation
 * following the OpenID Connect Core 1.0 specification.
 * </p>
 */
@DisplayName("DefaultAuthenticationProvider Tests")
@ExtendWith(MockitoExtension.class)
class DefaultAuthenticationProviderTest {

    private static final String CLIENT_ID = "client_12345";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String SUBJECT = "user_67890";
    private static final String NONCE = "nonce-123";
    
    @Mock
    private IdTokenGenerator idTokenGenerator;
    
    @Mock
    private UserRegistry userRegistry;
    
    @Mock
    private AuthenticationMethod authenticationMethod;
    
    private IdToken mockIdToken;
    
    private DefaultAuthenticationProvider provider;

    private static RSAKey rsaKey;
    private static ECKey ecKey;
    @BeforeEach
    void setUp() throws Exception {
        // Create a real DefaultIdTokenGenerator instead of mocking
        DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
            "https://issuer.example.com",
            "RS256",
            rsaKey.toRSAPrivateKey()
        );

        provider = new DefaultAuthenticationProvider(realGenerator, userRegistry);

        // Create a real IdToken instance instead of mocking
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss("https://issuer.example.com")
                .sub(SUBJECT)
                .aud(CLIENT_ID)
                .exp(Instant.now().plusSeconds(3600).getEpochSecond())
                .iat(Instant.now().getEpochSecond())
                .build();
        mockIdToken = IdToken.builder()
                .tokenValue("mock-token-value")
                .claims(claims)
                .build();
    }

    @BeforeAll
    static void setUpClass() throws Exception {
        // Generate RSA key for testing using the same approach as DefaultIdTokenValidatorTest
        com.nimbusds.jose.jwk.gen.RSAKeyGenerator rsaKeyGenerator = new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048);
        rsaKey = rsaKeyGenerator
                .keyID("rsa-key-1")
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .generate();

        // Generate EC key for testing
        com.nimbusds.jose.jwk.gen.ECKeyGenerator ecKeyGenerator = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256);
        ecKey = ecKeyGenerator
                .keyID("ec-key-1")
                .generate();
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should throw exception when idTokenGenerator is null")
        void shouldThrowExceptionWhenIdTokenGeneratorIsNull() {
            assertThatThrownBy(() -> new DefaultAuthenticationProvider(null, userRegistry))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("ID Token generator");
        }

        @Test
        @DisplayName("Should throw exception when userRegistry is null")
        void shouldThrowExceptionWhenUserRegistryIsNull() {
            assertThatThrownBy(() -> new DefaultAuthenticationProvider(idTokenGenerator, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("User registry");
        }

        @Test
        @DisplayName("Should create provider with max age")
        void shouldCreateProviderWithMaxAge() throws Exception {
            Long maxAge = 3600L;
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider provider = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, maxAge);

            assertThat(provider.getIdTokenGenerator()).isSameAs(realGenerator);
            assertThat(provider.getUserRegistry()).isSameAs(userRegistry);
            assertThat(provider.getMaxAge()).isEqualTo(maxAge);
        }

        @Test
        @DisplayName("Should create provider with authentication methods")
        void shouldCreateProviderWithAuthenticationMethods() throws Exception {
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider provider = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));
            
            assertThat(provider.getAuthenticationMethods()).hasSize(1);
            assertThat(provider.getAuthenticationMethods().get(0)).isSameAs(authenticationMethod);
        }
    }

    @Nested
    @DisplayName("authenticate(AuthenticationRequest)")
    class Authenticate {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> provider.authenticate(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authentication request");
        }

        @Test
        @DisplayName("Should throw exception for invalid request")
        void shouldThrowExceptionForInvalidRequest() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .state("test-state")
                    .build();

            assertThatThrownBy(() -> provider.authenticate(request))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Authentication credentials required");
        }

        @Test
        @DisplayName("Should authenticate valid request")
        void shouldAuthenticateValidRequest() throws Exception {
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .state("test-state")
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();

            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // Use a real generator with issuer - use toRSAPrivateKey() to get the private key
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );

            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            IdToken result = providerWithMethod.authenticate(request);

            assertThat(result).isNotNull();
            assertThat(result.getTokenValue()).isNotEmpty();
            assertThat(result.getClaims().getExp()).isGreaterThan(Instant.now().getEpochSecond());
        }

        @Test
        @DisplayName("Should authenticate user with max age")
        void shouldAuthenticateUserWithMaxAge() throws Exception {
            // Arrange
            Long maxAge = 1800L;
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMaxAge = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, maxAge, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .state("test-state")
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // Act
            IdToken result = providerWithMaxAge.authenticate(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getTokenValue()).isNotEmpty();
            long expectedExp = Instant.now().getEpochSecond() + maxAge;
            assertThat(result.getClaims().getExp()).isGreaterThanOrEqualTo(expectedExp - 1);
            assertThat(result.getClaims().getExp()).isLessThanOrEqualTo(expectedExp + 1);
        }

        @Test
        @DisplayName("Should reuse existing authentication within max age")
        void shouldReuseExistingAuthenticationWithinMaxAge() throws Exception {
            // Arrange
            Long maxAge = 3600L;
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMaxAge = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, maxAge, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .state("test-state")
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // First authentication
            IdToken result1 = providerWithMaxAge.authenticate(request);

            // Second authentication within max age - should reuse existing
            IdToken result2 = providerWithMaxAge.authenticate(request);

            // Assert
            assertThat(result1).isNotNull();
            assertThat(result2).isNotNull();
            // Both tokens should have the same auth_time since authentication was reused
            assertThat(result1.getClaims().getAuthTime()).isEqualTo(result2.getClaims().getAuthTime());
        }

        @Test
        @DisplayName("Should re-authenticate after max age expires")
        void shouldReAuthenticateAfterMaxAgeExpires() throws Exception {
            // Arrange
            Long maxAge = 1L; // Very short max age
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMaxAge = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, maxAge, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .state("test-state")
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // First authentication
            IdToken result1 = providerWithMaxAge.authenticate(request);
            long firstAuthTime = result1.getClaims().getAuthTime();

            // Wait for max age to expire and ensure we cross into the next second
            Thread.sleep(2000);

            // Second authentication after max age - should re-authenticate
            IdToken result2 = providerWithMaxAge.authenticate(request);
            long secondAuthTime = result2.getClaims().getAuthTime();

            // Assert
            assertThat(result1).isNotNull();
            assertThat(result2).isNotNull();
            // Second auth_time should be later than first (at least 2 seconds later due to sleep)
            assertThat(secondAuthTime).isGreaterThan(firstAuthTime);
            // Verify the time difference is at least 1 second (due to auth_time being in seconds)
            assertThat(secondAuthTime - firstAuthTime).isGreaterThanOrEqualTo(1);
        }

        @Test
        @DisplayName("Should add nonce to token when provided")
        void shouldAddNonceToTokenWhenProvided() throws Exception {
            // Arrange
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("id_token")
                    .nonce(NONCE)
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // Act
            IdToken result = providerWithMethod.authenticate(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getClaims().getNonce()).isEqualTo(NONCE);
        }

        @Test
        @DisplayName("Should add acr to token when provided")
        void shouldAddAcrToTokenWhenProvided() throws Exception {
            // Arrange
            String acrValues = "0 1 2";
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .acrValues(acrValues)
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // Act
            IdToken result = providerWithMethod.authenticate(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getClaims().getAcr()).isEqualTo("0");
        }

        @Test
        @DisplayName("Should add azp to token for implicit flow")
        void shouldAddAzpToTokenForImplicitFlow() throws Exception {
            // Arrange
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("id_token")
                    .nonce(NONCE)
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // Act
            IdToken result = providerWithMethod.authenticate(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getClaims().getAzp()).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should add amr to token from authentication result")
        void shouldAddAmrToTokenFromAuthenticationResult() throws Exception {
            // Arrange
            String[] amr = {"pwd", "mfa"};
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .build();

            AuthenticationResult authResult = new AuthenticationResult(SUBJECT, amr);
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // Act
            IdToken result = providerWithMethod.authenticate(request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getClaims().getAmr()).isEqualTo(amr);
        }

        @Test
        @DisplayName("Should throw exception when authentication method returns null")
        void shouldThrowExceptionWhenAuthenticationMethodReturnsNull() throws Exception {
            // Arrange
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .build();

            when(authenticationMethod.authenticate(any(), any())).thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> providerWithMethod.authenticate(request))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Authentication credentials required");
        }

        @Test
        @DisplayName("Should throw exception when authentication method throws exception")
        void shouldThrowExceptionWhenAuthenticationMethodThrowsException() throws Exception {
            // Arrange
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .build();

            when(authenticationMethod.authenticate(any(), any()))
                    .thenThrow(new AuthenticationException("Authentication failed"));

            // Act & Assert
            assertThatThrownBy(() -> providerWithMethod.authenticate(request))
                    .isInstanceOf(AuthenticationException.class)
                    .hasMessageContaining("Authentication failed");
        }

        @Test
        @DisplayName("Should return true for authenticated user")
        void shouldReturnTrueForAuthenticatedUser() throws Exception {
            // Arrange
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider providerWithMethod = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, null, java.util.List.of(authenticationMethod));

            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .build();

            AuthenticationResult authResult = createAuthenticationResult();
            when(authenticationMethod.authenticate(any(), any())).thenReturn(authResult);

            // First authenticate the user
            providerWithMethod.authenticate(request);

            // Act
            boolean authenticated = providerWithMethod.isAuthenticated(SUBJECT);

            // Assert
            assertThat(authenticated).isTrue();
        }
    }

    @Nested
    @DisplayName("validateRequest(AuthenticationRequest)")
    class ValidateRequest {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> provider.validateRequest(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Authentication request");
        }

        @Test
        @DisplayName("Should return false when client ID is missing")
        void shouldReturnFalseWhenClientIdIsMissing() {
            try {
                AuthenticationRequest.builder()
                        .redirectUri(REDIRECT_URI)
                        .scope("openid")
                        .responseType("code")
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject missing required field
                assertThat(e.getMessage()).contains("client_id is required");
            }
        }

        @Test
        @DisplayName("Should return false when redirect URI is missing")
        void shouldReturnFalseWhenRedirectUriIsMissing() {
            try {
                AuthenticationRequest.builder()
                        .clientId(CLIENT_ID)
                        .scope("openid")
                        .responseType("code")
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject missing required field
                assertThat(e.getMessage()).contains("redirect_uri is required");
            }
        }

        @Test
        @DisplayName("Should return false when scope is missing")
        void shouldReturnFalseWhenScopeIsMissing() {
            try {
                AuthenticationRequest.builder()
                        .clientId(CLIENT_ID)
                        .redirectUri(REDIRECT_URI)
                        .responseType("code")
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject missing required field
                assertThat(e.getMessage()).contains("scope is required");
            }
        }

        @Test
        @DisplayName("Should return false when scope does not include openid")
        void shouldReturnFalseWhenScopeDoesNotIncludeOpenid() {
            try {
                AuthenticationRequest.builder()
                        .clientId(CLIENT_ID)
                        .redirectUri(REDIRECT_URI)
                        .scope("profile email")
                        .responseType("code")
                        .build();
                // If we reach here, the builder should have thrown an exception
                assertThat(true).isFalse();
            } catch (IllegalStateException e) {
                // Expected: builder should reject invalid scope
                assertThat(e.getMessage()).contains("scope must include 'openid'");
            }
        }

        @Test
        @DisplayName("Should return false when response type is invalid")
        void shouldReturnFalseWhenResponseTypeIsInvalid() {
            // This test verifies the validateRequest method rejects invalid response types
            // The builder itself doesn't validate response type, the provider does
            boolean isValid = provider.validateRequest(
                AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("invalid")
                    .build()
            );
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false when nonce is missing for implicit flow")
        void shouldReturnFalseWhenNonceIsMissingForImplicitFlow() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("id_token")
                    .nonce(null)
                    .build();
            
            // Validate the request - nonce should be validated
            boolean isValid = provider.validateRequest(request);

            // For implicit flow, nonce should be required
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return true for valid authorization code flow request")
        void shouldReturnTrueForValidAuthorizationCodeFlowRequest() {
            AuthenticationRequest request = createValidRequest();
            
            boolean isValid = provider.validateRequest(request);
            
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid implicit flow request with nonce")
        void shouldReturnTrueForValidImplicitFlowRequest() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("id_token")
                    .nonce(NONCE)
                    .build();
            
            boolean isValid = provider.validateRequest(request);
            
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should validate max_age parameter")
        void shouldValidateMaxAgeParameter() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .maxAge(-1)
                    .build();

            boolean isValid = provider.validateRequest(request);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should validate request with valid max_age")
        void shouldValidateRequestWithValidMaxAge() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope("openid")
                    .responseType("code")
                    .maxAge(3600)
                    .build();

            boolean isValid = provider.validateRequest(request);

            assertThat(isValid).isTrue();
        }
    }

    @Nested
    @DisplayName("isAuthenticated(String)")
    class IsAuthenticated {

        @Test
        @DisplayName("Should throw exception when subject is null")
        void shouldThrowExceptionWhenSubjectIsNull() {
            assertThatThrownBy(() -> provider.isAuthenticated(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Subject");
        }

        @Test
        @DisplayName("Should return false for unauthenticated user")
        void shouldReturnFalseForUnauthenticatedUser() {
            boolean authenticated = provider.isAuthenticated(SUBJECT);
            
            assertThat(authenticated).isFalse();
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return max age")
        void shouldReturnMaxAge() throws Exception {
            Long maxAge = 3600L;
            DefaultIdTokenGenerator realGenerator = new DefaultIdTokenGenerator(
                "https://issuer.example.com",
                "RS256",
                rsaKey.toRSAPrivateKey()
            );
            DefaultAuthenticationProvider provider = new DefaultAuthenticationProvider(
                    realGenerator, userRegistry, maxAge);
            
            assertThat(provider.getMaxAge()).isEqualTo(maxAge);
        }

        @Test
        @DisplayName("Should return authentication sessions")
        void shouldReturnAuthenticationSessions() {
            var sessions = provider.getAuthenticationSessions();
            
            assertThat(sessions).isNotNull();
            assertThat(sessions).isEmpty();
        }
    }

    // Helper methods

    private AuthenticationRequest createValidRequest() {
        return AuthenticationRequest.builder()
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope("openid")
                .responseType("code")
                .build();
    }

    private AuthenticationRequest createInvalidRequest() {
        // This method is no longer needed as builder validates required fields
        // Tests now directly test builder validation
        return null;
    }

    private AuthenticationResult createAuthenticationResult() {
        return new AuthenticationResult(
                SUBJECT,
                new String[]{"pwd"}
        );
    }
}
