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
package com.alibaba.openagentauth.spring.web.model;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("OAuth2ErrorResponse Unit Tests")
class OAuth2ErrorResponseTest {

    @Nested
    @DisplayName("fromOAuth2Exception Factory Method")
    class FromOAuth2ExceptionTests {

        @Test
        @DisplayName("Should create response from DcrException with invalid_redirect_uri")
        void shouldCreateResponseFromDcrExceptionWithInvalidRedirectUri() {
            DcrException exception = DcrException.invalidRedirectUri("Invalid redirect URI");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_redirect_uri");
            assertThat(response.getErrorDescription()).contains("Invalid redirect URI");
            assertThat(response.getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should create response from DcrException with invalid_client_metadata")
        void shouldCreateResponseFromDcrExceptionWithInvalidClientMetadata() {
            DcrException exception = DcrException.invalidClientMetadata("Invalid client metadata");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_client_metadata");
            assertThat(response.getErrorDescription()).contains("Invalid client metadata");
            assertThat(response.getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should create response from DcrException with invalid_client_id (401)")
        void shouldCreateResponseFromDcrExceptionWithInvalidClientId() {
            DcrException exception = DcrException.invalidClientId("Invalid client ID");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_client");
            assertThat(response.getErrorDescription()).contains("Invalid client ID");
            assertThat(response.getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should create response from DcrException with unapproved_client (403)")
        void shouldCreateResponseFromDcrExceptionWithUnapprovedClient() {
            DcrException exception = DcrException.unapprovedClient("Client not approved");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("unauthorized_client");
            assertThat(response.getErrorDescription()).contains("Client not approved");
            assertThat(response.getHttpStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Should create response from ParException with missing parameter")
        void shouldCreateResponseFromParExceptionWithMissingParameter() {
            ParException exception = ParException.missingParameter("client_id");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_request");
            assertThat(response.getErrorDescription()).contains("Missing required parameter");
            assertThat(response.getHttpStatus()).isEqualTo(exception.getStatusCode());
        }

        @Test
        @DisplayName("Should create response from ParException with invalid parameter")
        void shouldCreateResponseFromParExceptionWithInvalidParameter() {
            ParException exception = ParException.invalidParameter("scope", "Invalid scope format");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_request");
            assertThat(response.getErrorDescription()).contains("Invalid scope");
            assertThat(response.getHttpStatus()).isEqualTo(exception.getStatusCode());
        }

        @Test
        @DisplayName("Should create response from ParException with authentication failed")
        void shouldCreateResponseFromParExceptionWithAuthenticationFailed() {
            ParException exception = ParException.authenticationFailed("Invalid client credentials");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_client");
            assertThat(response.getErrorDescription()).contains("Client authentication failed");
            assertThat(response.getHttpStatus()).isEqualTo(exception.getStatusCode());
        }

        @Test
        @DisplayName("Should create response from ParException with invalid redirect URI")
        void shouldCreateResponseFromParExceptionWithInvalidRedirectUri() {
            ParException exception = ParException.invalidRedirectUri("Invalid redirect URI format");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_redirect_uri");
            assertThat(response.getErrorDescription()).contains("Invalid redirect_uri");
            assertThat(response.getHttpStatus()).isEqualTo(exception.getStatusCode());
        }

        @Test
        @DisplayName("Should create response from ParException via httpResponseError with custom status")
        void shouldCreateResponseFromParExceptionWithHttpResponseError() {
            ParException exception = ParException.httpResponseError(403, "access_denied", "Access denied");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("access_denied");
            assertThat(response.getHttpStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Should create response from DcrException via httpResponseError with custom status")
        void shouldCreateResponseFromDcrExceptionWithHttpResponseError() {
            DcrException exception = DcrException.httpResponseError(502, "server_error", "Bad gateway");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("server_error");
            assertThat(response.getHttpStatus()).isEqualTo(502);
        }
    }

    @Nested
    @DisplayName("fromFrameworkException Factory Method")
    class FromFrameworkExceptionTests {

        @Test
        @DisplayName("Should create response from FrameworkOAuth2TokenException with invalid_request")
        void shouldCreateResponseFromFrameworkExceptionWithInvalidRequest() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidRequest("Missing parameter");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromFrameworkException(exception);

            assertThat(response.getError()).isEqualTo("invalid_request");
            assertThat(response.getErrorDescription()).isEqualTo("Missing parameter");
            assertThat(response.getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should create response from FrameworkOAuth2TokenException with invalid_client (401)")
        void shouldCreateResponseFromFrameworkExceptionWithInvalidClient() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidClient("Invalid credentials");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromFrameworkException(exception);

            assertThat(response.getError()).isEqualTo("invalid_client");
            assertThat(response.getErrorDescription()).isEqualTo("Invalid credentials");
            assertThat(response.getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should create response from FrameworkOAuth2TokenException with invalid_grant")
        void shouldCreateResponseFromFrameworkExceptionWithInvalidGrant() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidGrant("Expired token");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromFrameworkException(exception);

            assertThat(response.getError()).isEqualTo("invalid_grant");
            assertThat(response.getErrorDescription()).isEqualTo("Expired token");
            assertThat(response.getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should create response from FrameworkOAuth2TokenException with invalid_scope")
        void shouldCreateResponseFromFrameworkExceptionWithInvalidScope() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidScope("Invalid scope");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromFrameworkException(exception);

            assertThat(response.getError()).isEqualTo("invalid_scope");
            assertThat(response.getErrorDescription()).isEqualTo("Invalid scope");
            assertThat(response.getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should create response from FrameworkOAuth2TokenException with unauthorized_client (403)")
        void shouldCreateResponseFromFrameworkExceptionWithUnauthorizedClient() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.unauthorizedClient("Not authorized");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromFrameworkException(exception);

            assertThat(response.getError()).isEqualTo("unauthorized_client");
            assertThat(response.getErrorDescription()).isEqualTo("Not authorized");
            assertThat(response.getHttpStatus()).isEqualTo(403);
        }
    }

    @Nested
    @DisplayName("Standard Factory Methods")
    class StandardFactoryMethodsTests {

        @Test
        @DisplayName("Should create invalid_request error response (400)")
        void shouldCreateInvalidRequestErrorResponse() {
            String description = "The request is missing a required parameter";

            OAuth2ErrorResponse response = OAuth2ErrorResponse.invalidRequest(description);

            assertThat(response.getError()).isEqualTo(OAuth2RfcErrorCode.INVALID_REQUEST.getValue());
            assertThat(response.getErrorDescription()).isEqualTo(description);
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        }

        @Test
        @DisplayName("Should create server_error error response (500)")
        void shouldCreateServerErrorErrorResponse() {
            String description = "Internal server error";

            OAuth2ErrorResponse response = OAuth2ErrorResponse.serverError(description);

            assertThat(response.getError()).isEqualTo(OAuth2RfcErrorCode.SERVER_ERROR.getValue());
            assertThat(response.getErrorDescription()).isEqualTo(description);
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        @Test
        @DisplayName("Should create custom error response with specified parameters")
        void shouldCreateCustomErrorResponse() {
            String error = "custom_error";
            String description = "Custom error description";
            int httpStatus = 418;

            OAuth2ErrorResponse response = OAuth2ErrorResponse.of(error, description, httpStatus);

            assertThat(response.getError()).isEqualTo(error);
            assertThat(response.getErrorDescription()).isEqualTo(description);
            assertThat(response.getHttpStatus()).isEqualTo(httpStatus);
        }
    }

    @Nested
    @DisplayName("HTTP Status Code Mapping via fromOAuth2Exception")
    class HttpStatusMappingTests {

        @Test
        @DisplayName("Should map invalid_client to 401 via DcrException")
        void shouldMapInvalidClientTo401() {
            DcrException exception = DcrException.invalidClientId("Invalid client");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_client");
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        }

        @Test
        @DisplayName("Should map unauthorized_client to 403 via DcrException")
        void shouldMapUnauthorizedClientTo403() {
            DcrException exception = DcrException.unapprovedClient("Unauthorized client");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("unauthorized_client");
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        }

        @Test
        @DisplayName("Should map invalid_redirect_uri to 400 via DcrException")
        void shouldMapInvalidRedirectUriTo400() {
            DcrException exception = DcrException.invalidRedirectUri("Bad redirect");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("invalid_redirect_uri");
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        }

        @Test
        @DisplayName("Should map server_error to 500 via DcrException default constructor")
        void shouldMapServerErrorTo500() {
            DcrException exception = new DcrException("Server error");

            OAuth2ErrorResponse response = OAuth2ErrorResponse.fromOAuth2Exception(exception);

            assertThat(response.getError()).isEqualTo("server_error");
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        @Test
        @DisplayName("Should use invalidRequest factory method for 400 status")
        void shouldUseInvalidRequestFactoryFor400() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.invalidRequest("Bad request");

            assertThat(response.getError()).isEqualTo("invalid_request");
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        }

        @Test
        @DisplayName("Should use serverError factory method for 500 status")
        void shouldUseServerErrorFactoryFor500() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.serverError("Internal error");

            assertThat(response.getError()).isEqualTo("server_error");
            assertThat(response.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        @Test
        @DisplayName("Should use custom status via of factory method")
        void shouldUseCustomStatusViaOfFactory() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.of("custom_error", "Custom", 418);

            assertThat(response.getHttpStatus()).isEqualTo(418);
        }
    }

    @Nested
    @DisplayName("toResponseEntity Method")
    class ToResponseEntityTests {

        @Test
        @DisplayName("Should create ResponseEntity with correct status and body")
        void shouldCreateResponseEntityWithCorrectStatusAndBody() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.invalidRequest("Test error");

            ResponseEntity<OAuth2ErrorResponse> entity = response.toResponseEntity();

            assertThat(entity.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(entity.getBody()).isSameAs(response);
        }

        @Test
        @DisplayName("Should preserve error response fields in entity body")
        void shouldPreserveErrorResponseFieldsInEntityBody() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.serverError("Server error");

            ResponseEntity<OAuth2ErrorResponse> entity = response.toResponseEntity();

            assertThat(entity.getBody().getError()).isEqualTo("server_error");
            assertThat(entity.getBody().getErrorDescription()).isEqualTo("Server error");
            assertThat(entity.getBody().getHttpStatus()).isEqualTo(500);
        }
    }

    @Nested
    @DisplayName("Getter Methods")
    class GetterTests {

        @Test
        @DisplayName("Should return correct error code")
        void shouldReturnCorrectErrorCode() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.invalidRequest("Test");

            assertThat(response.getError()).isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should return correct error description")
        void shouldReturnCorrectErrorDescription() {
            String description = "Test error description";
            OAuth2ErrorResponse response = OAuth2ErrorResponse.invalidRequest(description);

            assertThat(response.getErrorDescription()).isEqualTo(description);
        }

        @Test
        @DisplayName("Should return correct HTTP status code")
        void shouldReturnCorrectHttpStatusCode() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.invalidRequest("Test");

            assertThat(response.getHttpStatus()).isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("toString Method")
    class ToStringTests {

        @Test
        @DisplayName("Should return string representation with all fields")
        void shouldReturnStringRepresentationWithAllFields() {
            OAuth2ErrorResponse response = OAuth2ErrorResponse.of(
                    "test_error", "Test description", 418
            );

            String result = response.toString();

            assertThat(result).contains("test_error");
            assertThat(result).contains("Test description");
            assertThat(result).contains("418");
        }
    }
}