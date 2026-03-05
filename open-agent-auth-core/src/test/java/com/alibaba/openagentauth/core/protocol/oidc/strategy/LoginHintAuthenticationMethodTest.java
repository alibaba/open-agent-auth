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
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginHintAuthenticationMethod Tests")
class LoginHintAuthenticationMethodTest {

    @Mock
    private UserRegistry userRegistry;

    private final LoginHintAuthenticationMethod authenticationMethod = new LoginHintAuthenticationMethod();

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create instance")
        void shouldCreateInstance() {
            // Act
            LoginHintAuthenticationMethod method = new LoginHintAuthenticationMethod();

            // Assert
            assertThat(method).isNotNull();
        }
    }

    @Nested
    @DisplayName("Authenticate Tests")
    class AuthenticateTests {

        @Test
        @DisplayName("Should return null when login_hint is not present")
        void shouldReturnNullWhenLoginHintIsNotPresent() throws AuthenticationException {
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
        @DisplayName("Should authenticate successfully with valid login_hint")
        void shouldAuthenticateSuccessfullyWithValidLoginHint() throws AuthenticationException {
            // Arrange
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId("client-123")
                    .redirectUri("https://example.com/callback")
                    .scope("openid")
                    .loginHint("user@example.com")
                    .build();

            // Act
            AuthenticationResult result = authenticationMethod.authenticate(request, userRegistry);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getSubject()).isEqualTo("user@example.com");
            assertThat(result.getAuthenticationMethods()).contains("none");
        }
    }
}
