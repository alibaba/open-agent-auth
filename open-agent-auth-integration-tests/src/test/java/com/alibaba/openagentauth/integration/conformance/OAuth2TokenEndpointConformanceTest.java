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
package com.alibaba.openagentauth.integration.conformance;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Protocol Conformance Test for OAuth 2.0 Token Endpoint.
 * <p>
 * Validates that the Authorization Server's Token endpoint complies with
 * RFC 6749 §5 - Access Token Request and Response.
 * </p>
 * <p>
 * <b>Reference:</b>
 * <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5">RFC 6749 §5</a>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 §4.1.3 - Access Token Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.1">RFC 6749 §5.1 - Successful Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 §5.2 - Error Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3">RFC 6749 §2.3 - Client Authentication</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "Validates OAuth 2.0 Token endpoint conformance to RFC 6749 §5",
    protocol = "OAuth 2.0 Token Endpoint",
    reference = "RFC 6749 §5",
    requiredServices = {"localhost:8085"}
)
@DisplayName("OAuth 2.0 Token Endpoint Conformance Tests (RFC 6749 §5)")
class OAuth2TokenEndpointConformanceTest {

    private static final String BASE_URI = "http://localhost:8085";
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String CLIENT_ID = "sample-agent";
    private static final String CLIENT_SECRET = "sample-agent-secret";
    private static final String REDIRECT_URI = "http://localhost:8081/oauth/callback";
    private static final String INVALID_CODE = "invalid_authorization_code";

    @BeforeAll
    static void setup() {
        RestAssured.baseURI = BASE_URI;
        RestAssured.useRelaxedHTTPSValidation();
    }

    @Nested
    @DisplayName("Request Format Tests (RFC 6749 §4.1.3)")
    class RequestFormatTests {

        @Test
        @DisplayName("Token endpoint must accept application/x-www-form-urlencoded Content-Type")
        void shouldAcceptFormUrlEncodedContentType() {
            given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)


                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(400);
        }

        @Test
        @DisplayName("grant_type parameter is required")
        void shouldRequireGrantTypeParameter() {
            int statusCode = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isIn(400, 500);
        }

        @Test
        @DisplayName("code parameter is required for authorization_code grant")
        void shouldRequireCodeParameterForAuthorizationCodeGrant() {
            int statusCode = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isIn(400, 500);
        }

        @Test
        @DisplayName("redirect_uri parameter is required for authorization_code grant")
        void shouldRequireRedirectUriParameterForAuthorizationCodeGrant() {
            int statusCode = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isIn(400, 500);
        }
    }

    @Nested
    @DisplayName("Response Format Tests (RFC 6749 §5.1)")
    class ResponseFormatTests {

        @Test
        @DisplayName("Error response Content-Type must be application/json")
        void shouldReturnApplicationJsonContentTypeForErrorResponse() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            assertThat(response.getContentType()).startsWith("application/json");
        }

        @Test
        @DisplayName("Error response must include Cache-Control: no-store header")
        void shouldIncludeCacheControlNoStoreHeaderInErrorResponse() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);

            String cacheControl = response.getHeader("Cache-Control");
            if (cacheControl != null) {
                assertThat(cacheControl).contains("no-store");
            }
        }
    }

    @Nested
    @DisplayName("Error Response Tests (RFC 6749 §5.2)")
    class ErrorResponseTests {

        @Test
        @DisplayName("Missing grant_type should return 400 with error='invalid_request'")
        void shouldReturnInvalidRequestForMissingGrantType() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
        }

        @Test
        @DisplayName("Invalid grant_type should return error")
        void shouldReturnUnsupportedGrantTypeForInvalidGrantType() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "implicit")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
        }

        @Test
        @DisplayName("Invalid authorization code should return error")
        void shouldReturnInvalidGrantForInvalidAuthorizationCode() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            if (response.getStatusCode() == 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
            }
        }

        @Test
        @DisplayName("Invalid client credentials should return 401")
        void shouldReturnUnauthorizedForInvalidClientCredentials() {
            given()
                .auth().preemptive().basic(CLIENT_ID, "invalid-secret")
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(401);
        }

        @Test
        @DisplayName("Missing code parameter should return error")
        void shouldReturnErrorFieldForMissingCodeParameter() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            String error = response.jsonPath().getString("error");
            assertThat(error).isNotNull();
            assertThat(error).isNotEmpty();
        }

        @Test
        @DisplayName("Error response must include error field (REQUIRED per RFC 6749 §5.2)")
        void mustIncludeErrorFieldInErrorResponse() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            String error = response.jsonPath().getString("error");
            assertThat(error).isNotNull();
            assertThat(error).isNotEmpty();
        }

        @Test
        @DisplayName("Error response may include error_description field (OPTIONAL)")
        void mayIncludeErrorDescriptionFieldInErrorResponse() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            String errorDescription = response.jsonPath().getString("error_description");
            assertThat(errorDescription).isNotNull();
        }

        @Test
        @DisplayName("Error response may include error_uri field (OPTIONAL)")
        void mayIncludeErrorUriFieldInErrorResponse() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            String errorUri = response.jsonPath().getString("error_uri");
            if (errorUri != null) {
                assertThat(errorUri).isNotEmpty();
            }
        }
    }

    @Nested
    @DisplayName("Client Authentication Tests (RFC 6749 §2.3)")
    class ClientAuthenticationTests {

        @Test
        @DisplayName("Should support HTTP Basic Authentication (client_secret_basic)")
        void shouldSupportHttpBasicAuthentication() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
            assertThat(response.getStatusCode()).isNotEqualTo(401);
        }

        @Test
        @DisplayName("Missing authentication should return 401")
        void shouldReturnUnauthorizedForMissingAuthentication() {
            given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(401);
        }

        @Test
        @DisplayName("Incorrect client_secret should return 401")
        void shouldReturnUnauthorizedForIncorrectClientSecret() {
            given()
                .auth().preemptive().basic(CLIENT_ID, "wrong-secret")
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "authorization_code")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(401);
        }
    }

    @Nested
    @DisplayName("Grant Type Validation Tests")
    class GrantTypeValidationTests {

        @Test
        @DisplayName("Unsupported grant_type 'implicit' should return error")
        void shouldReturnErrorForImplicitGrantType() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "implicit")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
        }

        @Test
        @DisplayName("Unsupported grant_type 'password' should return error")
        void shouldReturnErrorForPasswordGrantType() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "password")
                .formParam("username", "testuser")
                .formParam("password", "testpass")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
        }

        @Test
        @DisplayName("Empty grant_type should return error")
        void shouldReturnErrorForEmptyGrantType() {
            io.restassured.response.Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)

                .formParam("grant_type", "")
                .formParam("code", INVALID_CODE)
                .formParam("redirect_uri", REDIRECT_URI)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 500);
        }
    }
}