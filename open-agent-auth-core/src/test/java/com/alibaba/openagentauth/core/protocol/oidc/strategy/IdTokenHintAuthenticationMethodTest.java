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
package com.alibaba.openagentauth.core.protocol.oidc.strategy;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("IdTokenHintAuthenticationMethod Tests")
class IdTokenHintAuthenticationMethodTest {

    @Mock
    private IdTokenValidator idTokenValidator;

    @Mock
    private UserRegistry userRegistry;

    private IdTokenHintAuthenticationMethod authenticationMethod;

    @BeforeEach
    void setUp() {
        authenticationMethod = new IdTokenHintAuthenticationMethod(idTokenValidator);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create instance with valid validator")
        void shouldCreateInstanceWithValidValidator() {
            // Act
            IdTokenHintAuthenticationMethod method = new IdTokenHintAuthenticationMethod(idTokenValidator);

            // Assert
            assertThat(method).isNotNull();
            assertThat(method.getIdTokenValidator()).isEqualTo(idTokenValidator);
        }

        @Test
        @DisplayName("Should throw exception when validator is null")
        void shouldThrowExceptionWhenValidatorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new IdTokenHintAuthenticationMethod(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("Authenticate Tests")
    class AuthenticateTests {

        @Test
        @DisplayName("Should return null when id_token_hint is not present")
        void shouldReturnNullWhenIdTokenHintIsNotPresent() throws AuthenticationException {
            // Arrange
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId("client-123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .build();

            // Act
            AuthenticationResult result = authenticationMethod.authenticate(request, userRegistry);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should authenticate successfully with valid id_token_hint")
        void shouldAuthenticateSuccessfullyWithValidIdTokenHint() throws AuthenticationException, IdTokenException {
            // Arrange
            String idTokenHint = "valid.id.token.hint";
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId("client-123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .idTokenHint(idTokenHint)
                    .build();

            IdTokenClaims claims = IdTokenClaims.builder()
                    .sub("user-123")
                    .iss("client-123")
                    .aud("client-123")
                    .iat(Instant.now())
                    .exp(Instant.now().plusSeconds(3600))
                    .build();

            IdToken idToken = mock(IdToken.class);
            when(idToken.getClaims()).thenReturn(claims);
            when(idTokenValidator.validate(eq(idTokenHint), anyString(), anyString()))
                    .thenReturn(idToken);

            // Act
            AuthenticationResult result = authenticationMethod.authenticate(request, userRegistry);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getSubject()).isEqualTo("user-123");
        }

        @Test
        @DisplayName("Should throw exception when id_token_hint validation fails")
        void shouldThrowExceptionWhenIdTokenHintValidationFails() throws IdTokenException {
            // Arrange
            String idTokenHint = "invalid.id.token.hint";
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId("client-123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .idTokenHint(idTokenHint)
                    .build();

            when(idTokenValidator.validate(eq(idTokenHint), anyString(), anyString()))
                    .thenThrow(new IdTokenException("Invalid ID Token"));

            // Act & Assert
            assertThatThrownBy(() -> authenticationMethod.authenticate(request, userRegistry))
                    .isInstanceOf(AuthenticationException.class);
        }
    }
}
