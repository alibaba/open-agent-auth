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
package com.alibaba.openagentauth.framework.web;

import com.alibaba.openagentauth.framework.web.interceptor.AsUserIdpUserAuthInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AsUserIdpUserAuthInterceptor}.
 *
 * @since 1.0
 */
@DisplayName("AsUserIdpUserAuthInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class AsUserIdpUserAuthInterceptorTest {

    @Mock
    private HttpServletRequest request;

    private AsUserIdpUserAuthInterceptor interceptor;

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create interceptor with valid parameters")
        void shouldCreateInterceptorWithValidParameters() {
            // Act & Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with null excluded paths")
        void shouldCreateInterceptorWithNullExcludedPaths() {
            // Act
            AsUserIdpUserAuthInterceptor interceptor = new AsUserIdpUserAuthInterceptor(
                null,
                "https://as-idp.example.com",
                "test-client-id",
                "https://example.com/callback"
            );

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("buildAuthorizationUrl(HttpServletRequest, String)")
    class BuildAuthorizationUrl {

        @Test
        @DisplayName("Should build OAuth 2.0 authorization URL")
        void shouldBuildOAuth2AuthorizationUrl() {
            // Act
            String authUrl = testableInterceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(authUrl).contains("https://as-idp.example.com/oauth2/authorize");
            assertThat(authUrl).contains("response_type=code");
            assertThat(authUrl).contains("client_id=test-client-id");
            assertThat(authUrl).contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
            assertThat(authUrl).contains("scope=openid+profile+email");
            assertThat(authUrl).contains("state=test-state");
        }

        @Test
        @DisplayName("Should URL encode callback URL")
        void shouldUrlEncodeCallbackUrl() {
            // Arrange
            TestableAsUserIdpUserAuthInterceptor testInterceptor = new TestableAsUserIdpUserAuthInterceptor(
                List.of("/login"),
                "https://as-idp.example.com",
                "test-client-id",
                "https://example.com/callback?param=value"
            );

            // Act
            String authUrl = testInterceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(authUrl).contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue");
        }

        @Test
        @DisplayName("Should include state parameter")
        void shouldIncludeStateParameter() {
            // Act
            String authUrl = testableInterceptor.testBuildAuthorizationUrl(request, "custom-state-123");

            // Assert
            assertThat(authUrl).contains("state=custom-state-123");
        }
    }

    @Nested
    @DisplayName("generateState()")
    class GenerateState {

        @Test
        @DisplayName("Should generate unique state")
        void shouldGenerateUniqueState() {
            // Act
            String state1 = testableInterceptor.testGenerateState();
            String state2 = testableInterceptor.testGenerateState();

            // Assert
            assertThat(state1).isNotNull();
            assertThat(state2).isNotNull();
            assertThat(state1).isNotEqualTo(state2);
        }

        @Test
        @DisplayName("Should generate Base64 URL encoded state")
        void shouldGenerateBase64UrlEncodedState() {
            // Act
            String state = testableInterceptor.testGenerateState();

            // Assert
            assertThat(state).isNotNull();
            assertThat(state).doesNotContain("+");
            assertThat(state).doesNotContain("/");
            assertThat(state).doesNotContain("=");
        }

        @Test
        @DisplayName("Should generate state with sufficient entropy")
        void shouldGenerateStateWithSufficientEntropy() {
            // Act
            String state = testableInterceptor.testGenerateState();

            // Assert - Base64 of 32 bytes = 43 characters
            assertThat(state.length()).isEqualTo(43);
        }
    }

    /**
     * Testable subclass that exposes protected methods for testing.
     */
    private static class TestableAsUserIdpUserAuthInterceptor extends AsUserIdpUserAuthInterceptor {
        public TestableAsUserIdpUserAuthInterceptor(
                List<String> excludedPaths,
                String issuer,
                String clientId,
                String callbackUrl) {
            super(excludedPaths, issuer, clientId, callbackUrl);
        }

        public String testBuildAuthorizationUrl(HttpServletRequest request, String state) {
            return buildAuthorizationUrl(request, state);
        }

        public String testGenerateState() {
            return generateState();
        }
    }

    private TestableAsUserIdpUserAuthInterceptor testableInterceptor;

    @BeforeEach
    void setUp() {
        testableInterceptor = new TestableAsUserIdpUserAuthInterceptor(
            List.of("/login", "/callback"),
            "https://as-idp.example.com",
            "test-client-id",
            "https://example.com/callback"
        );
        interceptor = testableInterceptor;
    }
}
