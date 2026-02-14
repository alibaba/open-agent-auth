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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.client;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2AuthorizationClient}.
 * <p>
 * This test class validates the OAuth 2.0 authorization client implementation
 * following RFC 6749 specification.
 * </p>
 */
@DisplayName("DefaultOAuth2AuthorizationClient Tests")
class DefaultOAuth2AuthorizationClientTest {

    private DefaultOAuth2AuthorizationClient client;
    private static final String AUTHORIZATION_ENDPOINT = "https://as.example.com/authorize";

    private ServiceEndpointResolver mockServiceEndpointResolver;

    @BeforeEach
    void setUp() {
        mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
        when(mockServiceEndpointResolver.resolveProvider(anyString()))
                .thenReturn(AUTHORIZATION_ENDPOINT);
        client = new DefaultOAuth2AuthorizationClient(mockServiceEndpointResolver);
    }

    @Nested
    @DisplayName("buildAuthorizationUrl()")
    class BuildAuthorizationUrl {

        @Test
        @DisplayName("Should build authorization URL with request_uri")
        void shouldBuildAuthorizationUrlWithRequestUri() {
            // Arrange
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";

            // Act
            String url = client.buildAuthorizationUrl(requestUri);

            // Assert
            assertThat(url).isNotNull();
            assertThat(url).contains(AUTHORIZATION_ENDPOINT);
            // The client already URL-encodes the request_uri parameter
            assertThat(url).contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc123");
        }

        @Test
        @DisplayName("Should throw exception when request_uri is null")
        void shouldThrowExceptionWhenRequestUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.buildAuthorizationUrl(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request URI");
        }

        @Test
        @DisplayName("Should handle existing query parameters in endpoint")
        void shouldHandleExistingQueryParametersInEndpoint() {
            // Arrange
            String endpointWithQuery = "https://as.example.com/authorize?existing_param=value";
            ServiceEndpointResolver resolverWithQuery = mock(ServiceEndpointResolver.class);
            when(resolverWithQuery.resolveProvider(anyString()))
                    .thenReturn(endpointWithQuery);
            DefaultOAuth2AuthorizationClient clientWithQuery = 
                    new DefaultOAuth2AuthorizationClient(resolverWithQuery);
            String requestUri = "urn:ietf:params:oauth:request_uri:abc123";

            // Act
            String url = clientWithQuery.buildAuthorizationUrl(requestUri);

            // Assert
            assertThat(url).contains("existing_param=value");
            assertThat(url).contains("request_uri=");
        }
    }

    @Nested
    @DisplayName("handleCallback()")
    class HandleCallback {

        @Test
        @DisplayName("Should extract authorization code from callback")
        void shouldExtractAuthorizationCodeFromCallback() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?code=auth_code_123";

            // Act
            String code = client.handleCallback(callbackUrl);

            // Assert
            assertThat(code).isEqualTo("auth_code_123");
        }

        @Test
        @DisplayName("Should throw exception when callback URL is null")
        void shouldThrowExceptionWhenCallbackUrlIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.handleCallback(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Callback URL");
        }

        @Test
        @DisplayName("Should throw exception when callback contains error")
        void shouldThrowExceptionWhenCallbackContainsError() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?error=access_denied&error_description=User denied access";

            // Act & Assert
            assertThatThrownBy(() -> client.handleCallback(callbackUrl))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining("access_denied")
                    .hasMessageContaining("User denied access");
        }

        @Test
        @DisplayName("Should throw exception when callback has no code")
        void shouldThrowExceptionWhenCallbackHasNoCode() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?state=xyz";

            // Act & Assert
            assertThatThrownBy(() -> client.handleCallback(callbackUrl))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining("No authorization code found");
        }

        @Test
        @DisplayName("Should handle URL-encoded parameters")
        void shouldHandleUrlEncodedParameters() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?code=auth%20code%20with%20spaces";

            // Act
            String code = client.handleCallback(callbackUrl);

            // Assert
            assertThat(code).isEqualTo("auth code with spaces");
        }
    }

    @Nested
    @DisplayName("validateState()")
    class ValidateState {

        @Test
        @DisplayName("Should return true when states match")
        void shouldReturnTrueWhenStatesMatch() {
            // Arrange
            String state = "random_state_123";
            String expectedState = "random_state_123";

            // Act
            boolean isValid = client.validateState(state, expectedState);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should return false when states do not match")
        void shouldReturnFalseWhenStatesDoNotMatch() {
            // Arrange
            String state = "random_state_123";
            String expectedState = "different_state_456";

            // Act
            boolean isValid = client.validateState(state, expectedState);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when state is null")
        void shouldThrowExceptionWhenStateIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.validateState(null, "expected"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when expected state is null")
        void shouldThrowExceptionWhenExpectedStateIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.validateState("state", null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("extractCode()")
    class ExtractCode {

        @Test
        @DisplayName("Should extract code from callback URL")
        void shouldExtractCodeFromCallbackUrl() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?code=auth_code_123&state=xyz";

            // Act
            String code = client.extractCode(callbackUrl);

            // Assert
            assertThat(code).isEqualTo("auth_code_123");
        }

        @Test
        @DisplayName("Should return null when callback URL is null")
        void shouldReturnNullWhenCallbackUrlIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.extractCode(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should return null when no code in callback")
        void shouldReturnNullWhenNoCodeInCallback() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?state=xyz";

            // Act
            String code = client.extractCode(callbackUrl);

            // Assert
            assertThat(code).isNull();
        }
    }

    @Nested
    @DisplayName("extractError()")
    class ExtractError {

        @Test
        @DisplayName("Should extract error and description from callback")
        void shouldExtractErrorAndDescriptionFromCallback() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?error=access_denied&error_description=User%20denied%20access";

            // Act
            String[] error = client.extractError(callbackUrl);

            // Assert
            assertThat(error).isNotNull();
            assertThat(error).hasSize(2);
            assertThat(error[0]).isEqualTo("access_denied");
            assertThat(error[1]).isEqualTo("User denied access");
        }

        @Test
        @DisplayName("Should return null when no error in callback")
        void shouldReturnNullWhenNoErrorInCallback() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?code=auth_code_123";

            // Act
            String[] error = client.extractError(callbackUrl);

            // Assert
            assertThat(error).isNull();
        }

        @Test
        @DisplayName("Should return empty description when not provided")
        void shouldReturnEmptyDescriptionWhenNotProvided() {
            // Arrange
            String callbackUrl = "https://client.example.com/callback?error=access_denied";

            // Act
            String[] error = client.extractError(callbackUrl);

            // Assert
            assertThat(error).isNotNull();
            assertThat(error).hasSize(2);
            assertThat(error[0]).isEqualTo("access_denied");
            assertThat(error[1]).isEmpty();
        }

        @Test
        @DisplayName("Should throw exception when callback URL is null")
        void shouldThrowExceptionWhenCallbackUrlIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> client.extractError(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }


}
