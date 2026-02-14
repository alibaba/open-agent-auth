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
package com.alibaba.openagentauth.framework.web.callback;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2CallbackRequest}.
 * <p>
 * This test class verifies the behavior of the OAuth2CallbackRequest class,
 * including constructor, factory method, and error detection.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OAuth2CallbackRequest Tests")
@ExtendWith(MockitoExtension.class)
class OAuth2CallbackRequestTest {

    @Mock
    private HttpServletRequest httpRequest;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with all parameters")
        void shouldCreateRequestWithAllParameters() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                "access_denied",
                "User denied access",
                httpRequest
            );

            assertThat(request.getCode()).isEqualTo("auth-code");
            assertThat(request.getState()).isEqualTo("state-value");
            assertThat(request.getError()).isEqualTo("access_denied");
            assertThat(request.getErrorDescription()).isEqualTo("User denied access");
            assertThat(request.getHttpRequest()).isSameAs(httpRequest);
        }

        @Test
        @DisplayName("Should create request with only code and state")
        void shouldCreateRequestWithOnlyCodeAndState() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                null,
                null,
                httpRequest
            );

            assertThat(request.getCode()).isEqualTo("auth-code");
            assertThat(request.getState()).isEqualTo("state-value");
            assertThat(request.getError()).isNull();
            assertThat(request.getErrorDescription()).isNull();
        }

        @Test
        @DisplayName("Should create request with only error")
        void shouldCreateRequestWithOnlyError() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                null,
                null,
                "access_denied",
                "User denied access",
                httpRequest
            );

            assertThat(request.getCode()).isNull();
            assertThat(request.getState()).isNull();
            assertThat(request.getError()).isEqualTo("access_denied");
            assertThat(request.getErrorDescription()).isEqualTo("User denied access");
        }

        @Test
        @DisplayName("Should create request with null http request")
        void shouldCreateRequestWithNullHttpRequest() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                null,
                null,
                null
            );

            assertThat(request.getCode()).isEqualTo("auth-code");
            assertThat(request.getState()).isEqualTo("state-value");
            assertThat(request.getHttpRequest()).isNull();
        }
    }

    @Nested
    @DisplayName("Factory Method Tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("Should create request from HttpServletRequest with success response")
        void shouldCreateRequestFromHttpServletRequestWithSuccessResponse() {
            when(httpRequest.getParameter("code")).thenReturn("auth-code");
            when(httpRequest.getParameter("state")).thenReturn("state-value");
            when(httpRequest.getParameter("error")).thenReturn(null);
            when(httpRequest.getParameter("error_description")).thenReturn(null);

            OAuth2CallbackRequest request = OAuth2CallbackRequest.from(httpRequest);

            assertThat(request.getCode()).isEqualTo("auth-code");
            assertThat(request.getState()).isEqualTo("state-value");
            assertThat(request.getError()).isNull();
            assertThat(request.getErrorDescription()).isNull();
            assertThat(request.getHttpRequest()).isSameAs(httpRequest);
        }

        @Test
        @DisplayName("Should create request from HttpServletRequest with error response")
        void shouldCreateRequestFromHttpServletRequestWithErrorResponse() {
            when(httpRequest.getParameter("code")).thenReturn(null);
            when(httpRequest.getParameter("state")).thenReturn("state-value");
            when(httpRequest.getParameter("error")).thenReturn("access_denied");
            when(httpRequest.getParameter("error_description")).thenReturn("User denied access");

            OAuth2CallbackRequest request = OAuth2CallbackRequest.from(httpRequest);

            assertThat(request.getCode()).isNull();
            assertThat(request.getState()).isEqualTo("state-value");
            assertThat(request.getError()).isEqualTo("access_denied");
            assertThat(request.getErrorDescription()).isEqualTo("User denied access");
            assertThat(request.getHttpRequest()).isSameAs(httpRequest);
        }

        @Test
        @DisplayName("Should handle missing parameters")
        void shouldHandleMissingParameters() {
            when(httpRequest.getParameter("code")).thenReturn(null);
            when(httpRequest.getParameter("state")).thenReturn(null);
            when(httpRequest.getParameter("error")).thenReturn(null);
            when(httpRequest.getParameter("error_description")).thenReturn(null);

            OAuth2CallbackRequest request = OAuth2CallbackRequest.from(httpRequest);

            assertThat(request.getCode()).isNull();
            assertThat(request.getState()).isNull();
            assertThat(request.getError()).isNull();
            assertThat(request.getErrorDescription()).isNull();
        }

        @Test
        @DisplayName("Should handle empty strings")
        void shouldHandleEmptyStrings() {
            when(httpRequest.getParameter("code")).thenReturn("");
            when(httpRequest.getParameter("state")).thenReturn("");
            when(httpRequest.getParameter("error")).thenReturn("");
            when(httpRequest.getParameter("error_description")).thenReturn("");

            OAuth2CallbackRequest request = OAuth2CallbackRequest.from(httpRequest);

            assertThat(request.getCode()).isEqualTo("");
            assertThat(request.getState()).isEqualTo("");
            assertThat(request.getError()).isEqualTo("");
            assertThat(request.getErrorDescription()).isEqualTo("");
        }
    }

    @Nested
    @DisplayName("hasError() Tests")
    class HasErrorTests {

        @Test
        @DisplayName("Should return true when error is present")
        void shouldReturnTrueWhenErrorIsPresent() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                null,
                null,
                "access_denied",
                "User denied access",
                httpRequest
            );

            assertThat(request.hasError()).isTrue();
        }

        @Test
        @DisplayName("Should return false when error is null")
        void shouldReturnFalseWhenErrorIsNull() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                null,
                null,
                httpRequest
            );

            assertThat(request.hasError()).isFalse();
        }

        @Test
        @DisplayName("Should return false when error is empty string")
        void shouldReturnFalseWhenErrorIsEmptyString() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                null,
                null,
                "",
                null,
                httpRequest
            );

            assertThat(request.hasError()).isFalse();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return code")
        void shouldReturnCode() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                null,
                null,
                httpRequest
            );

            assertThat(request.getCode()).isEqualTo("auth-code");
        }

        @Test
        @DisplayName("Should return state")
        void shouldReturnState() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                null,
                null,
                httpRequest
            );

            assertThat(request.getState()).isEqualTo("state-value");
        }

        @Test
        @DisplayName("Should return error")
        void shouldReturnError() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                null,
                null,
                "access_denied",
                "User denied access",
                httpRequest
            );

            assertThat(request.getError()).isEqualTo("access_denied");
        }

        @Test
        @DisplayName("Should return error description")
        void shouldReturnErrorDescription() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                null,
                null,
                "access_denied",
                "User denied access",
                httpRequest
            );

            assertThat(request.getErrorDescription()).isEqualTo("User denied access");
        }

        @Test
        @DisplayName("Should return http request")
        void shouldReturnHttpRequest() {
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(
                "auth-code",
                "state-value",
                null,
                null,
                httpRequest
            );

            assertThat(request.getHttpRequest()).isSameAs(httpRequest);
        }
    }
}
