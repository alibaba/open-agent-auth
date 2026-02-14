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
package com.alibaba.openagentauth.framework.model.request;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AuthenticationRequest}.
 * <p>
 * This test class verifies the behavior of the AuthenticationRequest class,
 * including builder pattern, validation, and immutability.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuthenticationRequest Tests")
class AuthenticationRequestTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with all fields")
        void shouldBuildRequestWithAllFields() {
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("username", "testuser");
            credentials.put("password", "testpass");

            Map<String, Object> context = new HashMap<>();
            context.put("ip", "192.168.1.1");
            context.put("userAgent", "TestAgent/1.0");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credentials(credentials)
                .context(context)
                .build();

            assertThat(request.getAuthenticationMethod()).isEqualTo("password");
            assertThat(request.getCredentials()).hasSize(2);
            assertThat(request.getContext()).hasSize(2);
        }

        @Test
        @DisplayName("Should build request with single credential")
        void shouldBuildRequestWithSingleCredential() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("oauth2")
                .credential("token", "oauth-token")
                .build();

            assertThat(request.getAuthenticationMethod()).isEqualTo("oauth2");
            assertThat(request.getCredential("token")).isEqualTo("oauth-token");
        }

        @Test
        @DisplayName("Should build request with single context value")
        void shouldBuildRequestWithSingleContextValue() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("mfa")
                .context("deviceId", "device123")
                .build();

            assertThat(request.getAuthenticationMethod()).isEqualTo("mfa");
            assertThat(request.getContextValue("deviceId")).isEqualTo("device123");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credential("username", "user")
                .credential("password", "pass")
                .context("ip", "127.0.0.1")
                .build();

            assertThat(request).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when authentication method is not set")
        void shouldThrowExceptionWhenAuthenticationMethodIsNotSet() {
            assertThatThrownBy(() -> {
                AuthenticationRequest.builder().build();
            }).isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("Authentication method is required");
        }

        @Test
        @DisplayName("Should handle null credentials map")
        void shouldHandleNullCredentialsMap() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credentials(null)
                .build();

            assertThat(request.getCredentials()).isEmpty();
        }

        @Test
        @DisplayName("Should handle null context map")
        void shouldHandleNullContextMap() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .context(null)
                .build();

            assertThat(request.getContext()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("Should create immutable credentials map")
        void shouldCreateImmutableCredentialsMap() {
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("username", "testuser");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credentials(credentials)
                .build();

            assertThatThrownBy(() -> {
                request.getCredentials().put("new-key", "new-value");
            }).isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Should create immutable context map")
        void shouldCreateImmutableContextMap() {
            Map<String, Object> context = new HashMap<>();
            context.put("ip", "192.168.1.1");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .context(context)
                .build();

            assertThatThrownBy(() -> {
                request.getContext().put("new-key", "new-value");
            }).isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Should not affect original maps after build")
        void shouldNotAffectOriginalMapsAfterBuild() {
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("username", "testuser");

            Map<String, Object> context = new HashMap<>();
            context.put("ip", "192.168.1.1");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credentials(credentials)
                .context(context)
                .build();

            credentials.put("new-cred", "value");
            context.put("new-ctx", "value");

            assertThat(request.getCredentials()).hasSize(1);
            assertThat(request.getContext()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return authentication method")
        void shouldReturnAuthenticationMethod() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .build();

            assertThat(request.getAuthenticationMethod()).isEqualTo("password");
        }

        @Test
        @DisplayName("Should return credentials map")
        void shouldReturnCredentialsMap() {
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("username", "testuser");
            credentials.put("password", "testpass");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credentials(credentials)
                .build();

            assertThat(request.getCredentials()).hasSize(2);
        }

        @Test
        @DisplayName("Should return specific credential value")
        void shouldReturnSpecificCredentialValue() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credential("username", "testuser")
                .credential("password", "testpass")
                .build();

            assertThat(request.getCredential("username")).isEqualTo("testuser");
            assertThat(request.getCredential("password")).isEqualTo("testpass");
        }

        @Test
        @DisplayName("Should return null for non-existent credential")
        void shouldReturnNullForNonExistentCredential() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credential("username", "testuser")
                .build();

            assertThat(request.getCredential("password")).isNull();
        }

        @Test
        @DisplayName("Should return context map")
        void shouldReturnContextMap() {
            Map<String, Object> context = new HashMap<>();
            context.put("ip", "192.168.1.1");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .context(context)
                .build();

            assertThat(request.getContext()).hasSize(1);
        }

        @Test
        @DisplayName("Should return specific context value")
        void shouldReturnSpecificContextValue() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .context("ip", "192.168.1.1")
                .context("userAgent", "TestAgent")
                .build();

            assertThat(request.getContextValue("ip")).isEqualTo("192.168.1.1");
            assertThat(request.getContextValue("userAgent")).isEqualTo("TestAgent");
        }

        @Test
        @DisplayName("Should return null for non-existent context value")
        void shouldReturnNullForNonExistentContextValue() {
            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .context("ip", "192.168.1.1")
                .build();

            assertThat(request.getContextValue("userAgent")).isNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complex credential objects")
        void shouldHandleComplexCredentialObjects() {
            Map<String, Object> nested = new HashMap<>();
            nested.put("type", "RSA");
            nested.put("key", "key-value");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("certificate")
                .credential("certificate", nested)
                .build();

            assertThat(request.getCredential("certificate")).isInstanceOf(Map.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> cert = (Map<String, Object>) request.getCredential("certificate");
            assertThat(cert.get("type")).isEqualTo("RSA");
        }

        @Test
        @DisplayName("Should support multiple credentials from map")
        void shouldSupportMultipleCredentialsFromMap() {
            Map<String, Object> credentials = new HashMap<>();
            credentials.put("username", "testuser");
            credentials.put("password", "testpass");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .credentials(credentials)
                .build();

            assertThat(request.getCredentials()).hasSize(2);
        }

        @Test
        @DisplayName("Should support multiple context from map")
        void shouldSupportMultipleContextFromMap() {
            Map<String, Object> context = new HashMap<>();
            context.put("ip", "192.168.1.1");
            context.put("userAgent", "TestAgent/1.0");

            AuthenticationRequest request = AuthenticationRequest.builder()
                .authenticationMethod("password")
                .context(context)
                .build();

            assertThat(request.getContext()).hasSize(2);
        }
    }
}
