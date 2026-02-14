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
package com.alibaba.openagentauth.core.protocol.oauth2.token.oidc;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IdTokenGeneratorAdapter}.
 * <p>
 * This test class validates the ID Token generator adapter implementation
 * following the OpenID Connect Core 1.0 specification.
 * </p>
 */
@DisplayName("IdTokenGeneratorAdapter Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IdTokenGeneratorAdapterTest {

    @Mock
    private IdTokenGenerator idTokenGenerator;

    private IdTokenGeneratorAdapter adapter;
    private static final String ISSUER = "https://as.example.com";
    private static final String CLIENT_ID = "client-123";
    private static final String SUBJECT = "user_12345";
    private static final long EXPIRATION_SECONDS = 3600;

    @BeforeEach
    void setUp() {
        adapter = new IdTokenGeneratorAdapter(idTokenGenerator, EXPIRATION_SECONDS, ISSUER);
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create adapter with null idTokenGenerator")
        void shouldCreateAdapterWithNullIdTokenGenerator() {
            // Act & Assert
            IdTokenGeneratorAdapter adapterWithNull = new IdTokenGeneratorAdapter(null, EXPIRATION_SECONDS, ISSUER);
            assertThat(adapterWithNull).isNotNull();
        }

        @Test
        @DisplayName("Should create adapter with custom expiration")
        void shouldCreateAdapterWithCustomExpiration() {
            // Act
            IdTokenGeneratorAdapter customAdapter = new IdTokenGeneratorAdapter(
                    idTokenGenerator,
                    EXPIRATION_SECONDS,
                    ISSUER
            );

            // Assert
            assertThat(customAdapter).isNotNull();
            assertThat(customAdapter.getExpirationSeconds()).isEqualTo(EXPIRATION_SECONDS);
            assertThat(customAdapter.getIssuer()).isEqualTo(ISSUER);
        }

        @Test
        @DisplayName("Should create adapter with default expiration")
        void shouldCreateAdapterWithDefaultExpiration() {
            // Act
            IdTokenGeneratorAdapter defaultAdapter = new IdTokenGeneratorAdapter(
                    idTokenGenerator,
                    ISSUER
            );

            // Assert
            assertThat(defaultAdapter).isNotNull();
            assertThat(defaultAdapter.getExpirationSeconds()).isEqualTo(3600L);
            assertThat(defaultAdapter.getIssuer()).isEqualTo(ISSUER);
        }
    }

    @Nested
    @DisplayName("generateToken()")
    class GenerateToken {

        @Test
        @DisplayName("Should throw exception when authCode is null")
        void shouldThrowExceptionWhenAuthCodeIsNull() {
            // Arrange
            TokenRequest request = TokenRequest.builder()
                    .code("auth_code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> adapter.generateToken(null, request))
                    .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should throw OAuth2TokenException when request is null")
        void shouldThrowOAuth2TokenExceptionWhenRequestIsNull() {
            // Arrange
            AuthorizationCode authCode = createTestAuthorizationCode();

            // Act & Assert
            assertThatThrownBy(() -> adapter.generateToken(authCode, null))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Failed to generate access token");
        }

        @Test
        @DisplayName("Should generate ID Token successfully")
        void shouldGenerateIdTokenSuccessfully() {
            // Arrange
            AuthorizationCode authCode = createTestAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(authCode.getCode())
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .build();

            IdToken expectedIdToken = IdToken.builder()
                    .tokenValue("test_jwt_token")
                    .claims(createExpectedClaims())
                    .build();

            when(idTokenGenerator.generate(any(IdTokenClaims.class), eq(EXPIRATION_SECONDS)))
                    .thenReturn(expectedIdToken);

            // Act
            String result = adapter.generateToken(authCode, request);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result).isEqualTo("test_jwt_token");
            verify(idTokenGenerator).generate(any(IdTokenClaims.class), eq(EXPIRATION_SECONDS));
        }

        @Test
        @DisplayName("Should throw OAuth2TokenException when generation fails")
        void shouldThrowOAuth2TokenExceptionWhenGenerationFails() {
            // Arrange
            AuthorizationCode authCode = createTestAuthorizationCode();
            TokenRequest request = TokenRequest.builder()
                    .code(authCode.getCode())
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .build();

            when(idTokenGenerator.generate(any(IdTokenClaims.class), eq(EXPIRATION_SECONDS)))
                    .thenThrow(new RuntimeException("Token generation failed"));

            // Act & Assert
            assertThatThrownBy(() -> adapter.generateToken(authCode, request))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Failed to generate access token");
        }

        @Test
        @DisplayName("Should build correct ID Token claims")
        void shouldBuildCorrectIdTokenClaims() {
            // Arrange
            Instant authTime = Instant.now().minusSeconds(60);
            AuthorizationCode authCode = AuthorizationCode.builder()
                    .code("test_code")
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .subject(SUBJECT)
                    .issuedAt(authTime)
                    .expiresAt(authTime.plusSeconds(600))
                    .build();

            TokenRequest request = TokenRequest.builder()
                    .code(authCode.getCode())
                    .clientId(CLIENT_ID)
                    .redirectUri("https://example.com/callback")
                    .build();

            IdToken expectedIdToken = IdToken.builder()
                    .tokenValue("test_jwt_token")
                    .claims(createExpectedClaims())
                    .build();

            when(idTokenGenerator.generate(any(IdTokenClaims.class), eq(EXPIRATION_SECONDS)))
                    .thenAnswer(invocation -> {
                        IdTokenClaims claims = invocation.getArgument(0);
                        // Verify claims are built correctly
                        assertThat(claims.getIss()).isEqualTo(ISSUER);
                        assertThat(claims.getSub()).isEqualTo(SUBJECT);
                        assertThat(claims.getAud()).isEqualTo(CLIENT_ID);
                        assertThat(claims.getAuthTime()).isEqualTo(authTime.getEpochSecond());
                        return expectedIdToken;
                    });

            // Act
            adapter.generateToken(authCode, request);

            // Assert - verified in thenAnswer
            verify(idTokenGenerator).generate(any(IdTokenClaims.class), eq(EXPIRATION_SECONDS));
        }
    }

    @Nested
    @DisplayName("getExpirationSeconds()")
    class GetExpirationSeconds {

        @Test
        @DisplayName("Should return configured expiration time")
        void shouldReturnConfiguredExpirationTime() {
            // Act
            long expiration = adapter.getExpirationSeconds();

            // Assert
            assertThat(expiration).isEqualTo(EXPIRATION_SECONDS);
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return ID Token generator")
        void shouldReturnIdTokenGenerator() {
            // Act
            IdTokenGenerator generator = adapter.getIdTokenGenerator();

            // Assert
            assertThat(generator).isNotNull();
            assertThat(generator).isEqualTo(idTokenGenerator);
        }

        @Test
        @DisplayName("Should return default expiration time")
        void shouldReturnDefaultExpirationTime() {
            // Act
            long expiration = adapter.getDefaultExpirationSeconds();

            // Assert
            assertThat(expiration).isEqualTo(EXPIRATION_SECONDS);
        }

        @Test
        @DisplayName("Should return issuer")
        void shouldReturnIssuer() {
            // Act
            String issuer = adapter.getIssuer();

            // Assert
            assertThat(issuer).isEqualTo(ISSUER);
        }
    }

    /**
     * Creates a test authorization code.
     *
     * @return the test authorization code
     */
    private AuthorizationCode createTestAuthorizationCode() {
        Instant now = Instant.now();
        return AuthorizationCode.builder()
                .code("test_code")
                .clientId(CLIENT_ID)
                .redirectUri("https://example.com/callback")
                .subject(SUBJECT)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600))
                .build();
    }

    /**
     * Creates expected ID Token claims for verification.
     *
     * @return the expected claims
     */
    private IdTokenClaims createExpectedClaims() {
        Instant now = Instant.now();
        return IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(CLIENT_ID)
                .iat(now)
                .exp(now.plusSeconds(EXPIRATION_SECONDS))
                .authTime(now)
                .build();
    }
}
