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
package com.alibaba.openagentauth.framework.web.authorization;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AuthorizationResult}.
 * <p>
 * This test class verifies the behavior of the AuthorizationResult class,
 * including factory methods, getters, and result type handling.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuthorizationResult Tests")
class AuthorizationResultTest {

    @Nested
    @DisplayName("Factory Method Tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("Should create redirect result")
        void shouldCreateRedirectResult() {
            AuthorizationResult result = AuthorizationResult.redirect(
                "https://example.com/callback?code=123"
            );

            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
            assertThat(result.getRedirectUri()).isEqualTo("https://example.com/callback?code=123");
            assertThat(result.getConsentPage()).isNull();
            assertThat(result.getError()).isNull();
            assertThat(result.getErrorDescription()).isNull();
            assertThat(result.getHttpStatus()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            assertThatThrownBy(() -> {
                AuthorizationResult.redirect(null);
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("redirectUri");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is empty")
        void shouldThrowExceptionWhenRedirectUriIsEmpty() {
            assertThatThrownBy(() -> {
                AuthorizationResult.redirect("");
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("redirectUri");
        }

        @Test
        @DisplayName("Should create error result with default status 400")
        void shouldCreateErrorResultWithDefaultStatus400() {
            AuthorizationResult result = AuthorizationResult.error(
                "invalid_request",
                "Missing required parameter"
            );

            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("Missing required parameter");
            assertThat(result.getHttpStatus()).isEqualTo(400);
            assertThat(result.getRedirectUri()).isNull();
            assertThat(result.getConsentPage()).isNull();
        }

        @Test
        @DisplayName("Should create error result with null description")
        void shouldCreateErrorResultWithNullDescription() {
            AuthorizationResult result = AuthorizationResult.error("invalid_request", null);

            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isNull();
            assertThat(result.getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should throw exception when error is null")
        void shouldThrowExceptionWhenErrorIsNull() {
            assertThatThrownBy(() -> {
                AuthorizationResult.error(null, "description");
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("error");
        }

        @Test
        @DisplayName("Should throw exception when error is empty")
        void shouldThrowExceptionWhenErrorIsEmpty() {
            assertThatThrownBy(() -> {
                AuthorizationResult.error("", "description");
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("error");
        }

        @Test
        @DisplayName("Should create error result with custom status")
        void shouldCreateErrorResultWithCustomStatus() {
            AuthorizationResult result = AuthorizationResult.error(
                "invalid_request",
                "Invalid parameter",
                422
            );

            assertThat(result.getHttpStatus()).isEqualTo(422);
        }

        @Test
        @DisplayName("Should create unauthorized error result")
        void shouldCreateUnauthorizedErrorResult() {
            AuthorizationResult result = AuthorizationResult.unauthorized(
                "login_required",
                "User must authenticate"
            );

            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.ERROR);
            assertThat(result.getError()).isEqualTo("login_required");
            assertThat(result.getErrorDescription()).isEqualTo("User must authenticate");
            assertThat(result.getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should create consent page result")
        void shouldCreateConsentPageResult() {
            Object consentPage = new Object();
            AuthorizationResult result = AuthorizationResult.consentPage(consentPage);

            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.CONSENT_PAGE);
            assertThat(result.getConsentPage()).isSameAs(consentPage);
            assertThat(result.getRedirectUri()).isNull();
            assertThat(result.getError()).isNull();
            assertThat(result.getHttpStatus()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should throw exception when consentPage is null")
        void shouldThrowExceptionWhenConsentPageIsNull() {
            assertThatThrownBy(() -> {
                AuthorizationResult.consentPage(null);
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("consentPage");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return type")
        void shouldReturnType() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result.getType()).isEqualTo(AuthorizationResult.ResultType.REDIRECT);
        }

        @Test
        @DisplayName("Should return redirectUri for redirect result")
        void shouldReturnRedirectUriForRedirectResult() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result.getRedirectUri()).isEqualTo("https://example.com");
        }

        @Test
        @DisplayName("Should return null redirectUri for non-redirect result")
        void shouldReturnNullRedirectUriForNonRedirectResult() {
            AuthorizationResult result = AuthorizationResult.error("error", "description");

            assertThat(result.getRedirectUri()).isNull();
        }

        @Test
        @DisplayName("Should return consentPage for consent page result")
        void shouldReturnConsentPageForConsentPageResult() {
            Object consentPage = new Object();
            AuthorizationResult result = AuthorizationResult.consentPage(consentPage);

            assertThat(result.getConsentPage()).isSameAs(consentPage);
        }

        @Test
        @DisplayName("Should return null consentPage for non-consent page result")
        void shouldReturnNullConsentPageForNonConsentPageResult() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result.getConsentPage()).isNull();
        }

        @Test
        @DisplayName("Should return error for error result")
        void shouldReturnErrorForErrorResult() {
            AuthorizationResult result = AuthorizationResult.error("invalid_request", "description");

            assertThat(result.getError()).isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should return null error for non-error result")
        void shouldReturnNullErrorForNonErrorResult() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result.getError()).isNull();
        }

        @Test
        @DisplayName("Should return errorDescription for error result")
        void shouldReturnErrorDescriptionForErrorResult() {
            AuthorizationResult result = AuthorizationResult.error("invalid_request", "description");

            assertThat(result.getErrorDescription()).isEqualTo("description");
        }

        @Test
        @DisplayName("Should return null errorDescription for non-error result")
        void shouldReturnNullErrorDescriptionForNonErrorResult() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result.getErrorDescription()).isNull();
        }

        @Test
        @DisplayName("Should return httpStatus for error result")
        void shouldReturnHttpStatusForErrorResult() {
            AuthorizationResult result = AuthorizationResult.error("error", "description", 403);

            assertThat(result.getHttpStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Should return 0 for non-error result")
        void shouldReturn0ForNonErrorResult() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result.getHttpStatus()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("ResultType Enum Tests")
    class ResultTypeEnumTests {

        @Test
        @DisplayName("Should have REDIRECT type")
        void shouldHaveRedirectType() {
            assertThat(AuthorizationResult.ResultType.REDIRECT).isNotNull();
        }

        @Test
        @DisplayName("Should have ERROR type")
        void shouldHaveErrorType() {
            assertThat(AuthorizationResult.ResultType.ERROR).isNotNull();
        }

        @Test
        @DisplayName("Should have CONSENT_PAGE type")
        void shouldHaveConsentPageType() {
            assertThat(AuthorizationResult.ResultType.CONSENT_PAGE).isNotNull();
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when redirect results match")
        void shouldBeEqualWhenRedirectResultsMatch() {
            AuthorizationResult result1 = AuthorizationResult.redirect("https://example.com");
            AuthorizationResult result2 = AuthorizationResult.redirect("https://example.com");

            assertThat(result1).isEqualTo(result2);
            assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when error results match")
        void shouldBeEqualWhenErrorResultsMatch() {
            AuthorizationResult result1 = AuthorizationResult.error("error", "description", 400);
            AuthorizationResult result2 = AuthorizationResult.error("error", "description", 400);

            assertThat(result1).isEqualTo(result2);
            assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when types differ")
        void shouldNotBeEqualWhenTypesDiffer() {
            AuthorizationResult redirectResult = AuthorizationResult.redirect("https://example.com");
            AuthorizationResult errorResult = AuthorizationResult.error("error", "description");

            assertThat(redirectResult).isNotEqualTo(errorResult);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            assertThat(result).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include type in toString")
        void shouldIncludeTypeInToString() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            String toString = result.toString();
            assertThat(toString).contains("REDIRECT");
        }

        @Test
        @DisplayName("Should include redirectUri in toString for redirect result")
        void shouldIncludeRedirectUriInToStringForRedirectResult() {
            AuthorizationResult result = AuthorizationResult.redirect("https://example.com");

            String toString = result.toString();
            assertThat(toString).contains("https://example.com");
        }

        @Test
        @DisplayName("Should include error in toString for error result")
        void shouldIncludeErrorInToStringForErrorResult() {
            AuthorizationResult result = AuthorizationResult.error("invalid_request", "description");

            String toString = result.toString();
            assertThat(toString).contains("invalid_request");
            assertThat(toString).contains("description");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle different OAuth error codes")
        void shouldHandleDifferentOAuthErrorCodes() {
            AuthorizationResult invalidRequest = AuthorizationResult.error("invalid_request", "description");
            AuthorizationResult unauthorizedClient = AuthorizationResult.error("unauthorized_client", "description");
            AuthorizationResult accessDenied = AuthorizationResult.error("access_denied", "description");

            assertThat(invalidRequest.getError()).isEqualTo("invalid_request");
            assertThat(unauthorizedClient.getError()).isEqualTo("unauthorized_client");
            assertThat(accessDenied.getError()).isEqualTo("access_denied");
        }

        @Test
        @DisplayName("Should handle different HTTP status codes")
        void shouldHandleDifferentHttpStatusCodes() {
            AuthorizationResult badRequest = AuthorizationResult.error("error", "description", 400);
            AuthorizationResult unauthorized = AuthorizationResult.error("error", "description", 401);
            AuthorizationResult forbidden = AuthorizationResult.error("error", "description", 403);
            AuthorizationResult serverError = AuthorizationResult.error("error", "description", 500);

            assertThat(badRequest.getHttpStatus()).isEqualTo(400);
            assertThat(unauthorized.getHttpStatus()).isEqualTo(401);
            assertThat(forbidden.getHttpStatus()).isEqualTo(403);
            assertThat(serverError.getHttpStatus()).isEqualTo(500);
        }
    }
}
