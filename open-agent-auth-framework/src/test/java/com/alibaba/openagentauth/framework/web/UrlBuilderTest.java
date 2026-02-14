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

import com.alibaba.openagentauth.framework.web.interceptor.UrlBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UrlBuilder}.
 *
 * @since 1.0
 */
@DisplayName("UrlBuilder Tests")
@ExtendWith(MockitoExtension.class)
class UrlBuilderTest {

    @Mock
    private HttpServletRequest request;

    @Nested
    @DisplayName("buildBaseUrl(HttpServletRequest)")
    class BuildBaseUrl {

        @Test
        @DisplayName("Should build base URL for HTTP with default port")
        void shouldBuildBaseUrlForHttpWithDefaultPort() {
            // Arrange
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(80);
            when(request.getContextPath()).thenReturn("");

            // Act
            String baseUrl = UrlBuilder.buildBaseUrl(request);

            // Assert
            assertThat(baseUrl).isEqualTo("http://example.com");
        }

        @Test
        @DisplayName("Should build base URL for HTTPS with default port")
        void shouldBuildBaseUrlForHttpsWithDefaultPort() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");

            // Act
            String baseUrl = UrlBuilder.buildBaseUrl(request);

            // Assert
            assertThat(baseUrl).isEqualTo("https://example.com");
        }

        @Test
        @DisplayName("Should build base URL for HTTP with custom port")
        void shouldBuildBaseUrlForHttpWithCustomPort() {
            // Arrange
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getContextPath()).thenReturn("");

            // Act
            String baseUrl = UrlBuilder.buildBaseUrl(request);

            // Assert
            assertThat(baseUrl).isEqualTo("http://example.com:8080");
        }

        @Test
        @DisplayName("Should build base URL for HTTPS with custom port")
        void shouldBuildBaseUrlForHttpsWithCustomPort() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(8443);
            when(request.getContextPath()).thenReturn("");

            // Act
            String baseUrl = UrlBuilder.buildBaseUrl(request);

            // Assert
            assertThat(baseUrl).isEqualTo("https://example.com:8443");
        }

        @Test
        @DisplayName("Should build base URL with context path")
        void shouldBuildBaseUrlWithContextPath() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");

            // Act
            String baseUrl = UrlBuilder.buildBaseUrl(request);

            // Assert
            assertThat(baseUrl).isEqualTo("https://example.com/app");
        }

        @Test
        @DisplayName("Should build base URL with context path and custom port")
        void shouldBuildBaseUrlWithContextPathAndCustomPort() {
            // Arrange
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(9090);
            when(request.getContextPath()).thenReturn("/myapp");

            // Act
            String baseUrl = UrlBuilder.buildBaseUrl(request);

            // Assert
            assertThat(baseUrl).isEqualTo("http://example.com:9090/myapp");
        }
    }

    @Nested
    @DisplayName("buildUrl(HttpServletRequest, String)")
    class BuildUrl {

        @Test
        @DisplayName("Should build full URL with path")
        void shouldBuildFullUrlWithPath() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");

            // Act
            String url = UrlBuilder.buildUrl(request, "/callback");

            // Assert
            assertThat(url).isEqualTo("https://example.com/callback");
        }

        @Test
        @DisplayName("Should build full URL with path and context path")
        void shouldBuildFullUrlWithPathAndContextPath() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");

            // Act
            String url = UrlBuilder.buildUrl(request, "/callback");

            // Assert
            assertThat(url).isEqualTo("https://example.com/app/callback");
        }

        @Test
        @DisplayName("Should build full URL with custom port and path")
        void shouldBuildFullUrlWithCustomPortAndPath() {
            // Arrange
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getContextPath()).thenReturn("");

            // Act
            String url = UrlBuilder.buildUrl(request, "/login");

            // Assert
            assertThat(url).isEqualTo("http://example.com:8080/login");
        }
    }

    @Nested
    @DisplayName("buildCurrentRequestUrl(HttpServletRequest)")
    class BuildCurrentRequestUrl {

        @Test
        @DisplayName("Should build current request URL without query string")
        void shouldBuildCurrentRequestUrlWithoutQueryString() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn(null);

            // Act
            String url = UrlBuilder.buildCurrentRequestUrl(request);

            // Assert
            assertThat(url).isEqualTo("https://example.com/oauth2/authorize");
        }

        @Test
        @DisplayName("Should build current request URL with query string")
        void shouldBuildCurrentRequestUrlWithQueryString() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn("response_type=code&client_id=test");

            // Act
            String url = UrlBuilder.buildCurrentRequestUrl(request);

            // Assert
            assertThat(url).isEqualTo("https://example.com/oauth2/authorize?response_type=code&client_id=test");
        }

        @Test
        @DisplayName("Should build current request URL with context path")
        void shouldBuildCurrentRequestUrlWithContextPath() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn(null);

            // Act
            String url = UrlBuilder.buildCurrentRequestUrl(request);

            // Assert
            assertThat(url).isEqualTo("https://example.com/app/oauth2/authorize");
        }

        @Test
        @DisplayName("Should build current request URL with empty query string")
        void shouldBuildCurrentRequestUrlWithEmptyQueryString() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn("");

            // Act
            String url = UrlBuilder.buildCurrentRequestUrl(request);

            // Assert
            assertThat(url).isEqualTo("https://example.com/oauth2/authorize");
        }
    }

    @Nested
    @DisplayName("buildUrlWithParams(String, String...)")
    class BuildUrlWithParams {

        @Test
        @DisplayName("Should build URL with single parameter")
        void shouldBuildUrlWithSingleParameter() {
            // Act
            String url = UrlBuilder.buildUrlWithParams("https://example.com/oauth2/authorize", "code", "12345");

            // Assert
            assertThat(url).isEqualTo("https://example.com/oauth2/authorize?code=12345");
        }

        @Test
        @DisplayName("Should build URL with multiple parameters")
        void shouldBuildUrlWithMultipleParameters() {
            // Act
            String url = UrlBuilder.buildUrlWithParams(
                "https://example.com/oauth2/authorize",
                "response_type", "code",
                "client_id", "test-client",
                "redirect_uri", "https://example.com/callback"
            );

            // Assert
            assertThat(url).isEqualTo("https://example.com/oauth2/authorize?response_type=code&client_id=test-client&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback");
        }

        @Test
        @DisplayName("Should URL encode parameter values")
        void shouldUrlEncodeParameterValues() {
            // Act
            String url = UrlBuilder.buildUrlWithParams(
                "https://example.com/oauth2/authorize",
                "redirect_uri", "https://example.com/callback?param=value"
            );

            // Assert
            assertThat(url).contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue");
        }

        @Test
        @DisplayName("Should throw exception for odd number of parameters")
        void shouldThrowExceptionForOddNumberOfParameters() {
            // Act & Assert
            assertThatThrownBy(() -> UrlBuilder.buildUrlWithParams(
                    "https://example.com",
                    "key1", "value1", "key2"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Params must be in key-value pairs");
        }

        @Test
        @DisplayName("Should throw exception for empty parameters")
        void shouldThrowExceptionForEmptyParameters() {
            // Act
            String url = UrlBuilder.buildUrlWithParams("https://example.com");

            // Assert - Empty params should just add "?"
            assertThat(url).isEqualTo("https://example.com?");
        }

        @Test
        @DisplayName("Should handle special characters in parameter values")
        void shouldHandleSpecialCharactersInParameterValues() {
            // Act
            String url = UrlBuilder.buildUrlWithParams(
                "https://example.com",
                "param", "value with spaces & special=chars"
            );

            // Assert
            assertThat(url).contains("param=value+with+spaces+%26+special%3Dchars");
        }

        @Test
        @DisplayName("Should handle UTF-8 characters in parameter values")
        void shouldHandleUtf8CharactersInParameterValues() {
            // Act
            String url = UrlBuilder.buildUrlWithParams(
                "https://example.com",
                "name", "Zhang San"
            );

            // Assert
            assertThat(url).contains("name=Zhang+San");
        }
    }
}
