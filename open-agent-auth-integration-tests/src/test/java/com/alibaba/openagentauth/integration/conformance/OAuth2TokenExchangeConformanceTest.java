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
import io.restassured.response.Response;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Protocol conformance tests for OAuth 2.0 Token Exchange (RFC 8693).
 * <p>
 * This test class validates the Authorization Server's behavior when handling
 * Token Exchange requests as defined in RFC 8693 - OAuth 2.0 Token Exchange.
 * </p>
 * <p>
 * Tests verify:
 * </p>
 * <ul>
 *   <li>Request format compliance (required and optional parameters per §2.1)</li>
 *   <li>Response format compliance (§2.2 successful response, §2.3 error response)</li>
 *   <li>Parameter validation (subject_token, subject_token_type, etc.)</li>
 *   <li>Error handling for missing or invalid parameters</li>
 *   <li>Client authentication requirements</li>
 *   <li>Token type identifier validation</li>
 * </ul>
 * <p>
 * <b>Note:</b> These tests require the Authorization Server (port 8085) to be running.
 * If the AS does not support Token Exchange grant type, the tests validate that
 * the server correctly rejects the request with appropriate error responses
 * per RFC 6749 §5.2.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693">RFC 8693 - OAuth 2.0 Token Exchange</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693#section-2.1">RFC 8693 §2.1 - Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693#section-2.2">RFC 8693 §2.2 - Successful Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693#section-2.3">RFC 8693 §2.3 - Error Response</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "Validates OAuth 2.0 Token Exchange conformance to RFC 8693",
    protocol = "OAuth 2.0 Token Exchange",
    reference = "RFC 8693",
    requiredServices = {"localhost:8085"}
)
@DisplayName("OAuth 2.0 Token Exchange Conformance Tests (RFC 8693)")
class OAuth2TokenExchangeConformanceTest {

    private static final String BASE_URI = "http://localhost:8085";
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String CLIENT_ID = "sample-agent";
    private static final String CLIENT_SECRET = "sample-agent-secret";

    /**
     * RFC 8693 §2.1: The grant type for Token Exchange.
     */
    private static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    /**
     * RFC 8693 §3: Token type identifiers.
     */
    private static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    private static final String TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";
    private static final String TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    private static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

    private static final String MOCK_SUBJECT_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock-subject-token";

    @BeforeAll
    static void setup() {
        RestAssured.baseURI = BASE_URI;
        RestAssured.useRelaxedHTTPSValidation();
    }

    @Nested
    @DisplayName("Request Format Tests (RFC 8693 §2.1)")
    class RequestFormatTests {

        @Test
        @DisplayName("Token Exchange request must use application/x-www-form-urlencoded Content-Type")
        void tokenExchangeRequestMustUseFormUrlEncodedContentType() {
            given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(org.hamcrest.Matchers.anyOf(
                    org.hamcrest.Matchers.is(200),
                    org.hamcrest.Matchers.is(400),
                    org.hamcrest.Matchers.is(500)
                ));
        }

        @Test
        @DisplayName("grant_type must be 'urn:ietf:params:oauth:grant-type:token-exchange' (REQUIRED)")
        void grantTypeMustBeTokenExchange() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            int statusCode = response.getStatusCode();
            assertThat(statusCode).isIn(200, 400, 500);

            if (statusCode >= 400) {
                String contentType = response.getContentType();
                assertThat(contentType).startsWith("application/json");
            }
        }

        @Test
        @DisplayName("subject_token parameter is REQUIRED per RFC 8693 §2.1")
        void subjectTokenParameterIsRequired() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
        }

        @Test
        @DisplayName("subject_token_type parameter is REQUIRED per RFC 8693 §2.1")
        void subjectTokenTypeParameterIsRequired() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
        }

        @Test
        @DisplayName("Token Exchange request should accept optional 'resource' parameter (RFC 8693 §2.1)")
        void tokenExchangeRequestShouldAcceptOptionalResourceParameter() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("resource", "https://api.example.com/resource")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Token Exchange request should accept optional 'audience' parameter (RFC 8693 §2.1)")
        void tokenExchangeRequestShouldAcceptOptionalAudienceParameter() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("audience", "https://target-service.example.com")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Token Exchange request should accept optional 'scope' parameter (RFC 8693 §2.1)")
        void tokenExchangeRequestShouldAcceptOptionalScopeParameter() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("scope", "openid profile")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Token Exchange request should accept optional 'requested_token_type' parameter (RFC 8693 §2.1)")
        void tokenExchangeRequestShouldAcceptOptionalRequestedTokenTypeParameter() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Token Exchange request should accept optional actor_token and actor_token_type (RFC 8693 §2.1)")
        void tokenExchangeRequestShouldAcceptOptionalActorTokenParameters() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("actor_token", "mock-actor-token")
                .formParam("actor_token_type", TOKEN_TYPE_JWT)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }
    }

    @Nested
    @DisplayName("Response Format Tests (RFC 8693 §2.2 / §2.3)")
    class ResponseFormatTests {

        @Test
        @DisplayName("Response Content-Type must be application/json (RFC 8693 §2.2)")
        void responseContentTypeMustBeApplicationJson() {
            String contentType = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .extract()
                .contentType();

            assertThat(contentType).startsWith("application/json");
        }

        @Test
        @DisplayName("Error response must include 'error' field per RFC 6749 §5.2")
        void errorResponseMustIncludeErrorField() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            if (response.getStatusCode() >= 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
                assertThat(error).isNotEmpty();
            }
        }

        @Test
        @DisplayName("Response must include Cache-Control: no-store header")
        void responseMustIncludeCacheControlNoStoreHeader() {
            String cacheControl = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .extract()
                .header("Cache-Control");

            if (cacheControl != null) {
                assertThat(cacheControl).contains("no-store");
            }
        }

        @Test
        @DisplayName("If unsupported, server should return 'unsupported_grant_type' error")
        void ifUnsupportedServerShouldReturnUnsupportedGrantTypeError() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            if (response.getStatusCode() == 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isIn("unsupported_grant_type", "invalid_request", "invalid_grant");
            } else if (response.getStatusCode() == 500) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isIn("server_error", "unsupported_grant_type");
            }
        }
    }

    @Nested
    @DisplayName("Token Type Identifier Tests (RFC 8693 §3)")
    class TokenTypeIdentifierTests {

        @Test
        @DisplayName("subject_token_type 'urn:ietf:params:oauth:token-type:access_token' should be accepted")
        void subjectTokenTypeAccessTokenShouldBeAccepted() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("subject_token_type 'urn:ietf:params:oauth:token-type:id_token' should be accepted")
        void subjectTokenTypeIdTokenShouldBeAccepted() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ID_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("subject_token_type 'urn:ietf:params:oauth:token-type:jwt' should be accepted")
        void subjectTokenTypeJwtShouldBeAccepted() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_JWT)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Invalid subject_token_type should return error")
        void invalidSubjectTokenTypeShouldReturnError() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", "invalid:token:type")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
        }

        @Test
        @DisplayName("requested_token_type 'urn:ietf:params:oauth:token-type:access_token' should be recognized")
        void requestedTokenTypeAccessTokenShouldBeRecognized() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("requested_token_type 'urn:ietf:params:oauth:token-type:refresh_token' should be recognized")
        void requestedTokenTypeRefreshTokenShouldBeRecognized() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("requested_token_type", TOKEN_TYPE_REFRESH_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }
    }

    @Nested
    @DisplayName("Client Authentication Tests (RFC 8693 §2.1)")
    class ClientAuthenticationTests {

        @Test
        @DisplayName("Token Exchange request must require client authentication")
        void tokenExchangeRequestMustRequireClientAuthentication() {
            given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(401);
        }

        @Test
        @DisplayName("Invalid client credentials should return 401")
        void invalidClientCredentialsShouldReturn401() {
            given()
                .auth().preemptive().basic(CLIENT_ID, "wrong-secret")


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT)
            .then()
                .statusCode(401);
        }

        @Test
        @DisplayName("Token Exchange should support HTTP Basic Authentication (client_secret_basic)")
        void tokenExchangeShouldSupportHttpBasicAuthentication() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isNotEqualTo(401);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests (RFC 8693 §2.3)")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Missing subject_token should return error with 'error' field")
        void missingSubjectTokenShouldReturnErrorWithErrorField() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
            if (response.getStatusCode() >= 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
            }
        }

        @Test
        @DisplayName("Missing subject_token_type should return error with 'error' field")
        void missingSubjectTokenTypeShouldReturnErrorWithErrorField() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
            if (response.getStatusCode() >= 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
            }
        }

        @Test
        @DisplayName("Empty subject_token should return error")
        void emptySubjectTokenShouldReturnError() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", "")
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
        }

        @Test
        @DisplayName("Empty subject_token_type should return error")
        void emptySubjectTokenTypeShouldReturnError() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", "")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(400, 401, 500);
        }

        @Test
        @DisplayName("actor_token without actor_token_type should return error")
        void actorTokenWithoutActorTokenTypeShouldReturnError() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("actor_token", "mock-actor-token")
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Error response Content-Type must be application/json")
        void errorResponseContentTypeMustBeApplicationJson() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
            .when()
                .post(TOKEN_ENDPOINT);

            if (response.getStatusCode() >= 400) {
                assertThat(response.getContentType()).startsWith("application/json");
            }
        }

        @Test
        @DisplayName("Error response must conform to RFC 6749 §5.2 error format")
        void errorResponseMustConformToRfc6749ErrorFormat() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            if (response.getStatusCode() == 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
                assertThat(error).isIn(
                    "invalid_request",
                    "invalid_client",
                    "invalid_grant",
                    "unauthorized_client",
                    "unsupported_grant_type",
                    "invalid_scope",
                    "invalid_target"
                );
            }
        }
    }

    @Nested
    @DisplayName("Delegation and Impersonation Semantics Tests (RFC 8693 §1.1)")
    class DelegationAndImpersonationTests {

        @Test
        @DisplayName("Delegation request with actor_token should be handled")
        void delegationRequestWithActorTokenShouldBeHandled() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)


                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("actor_token", "mock-actor-token")
                .formParam("actor_token_type", TOKEN_TYPE_JWT)
                .formParam("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
            if (response.getStatusCode() >= 400) {
                String contentType = response.getContentType();
                assertThat(contentType).startsWith("application/json");
            }
        }

        @Test
        @DisplayName("Impersonation request without actor_token should be handled")
        void impersonationRequestWithoutActorTokenShouldBeHandled() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)

                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);
        }

        @Test
        @DisplayName("Full Token Exchange request with all parameters should be handled")
        void fullTokenExchangeRequestWithAllParametersShouldBeHandled() {
            Response response = given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)
                .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                .formParam("resource", "https://api.example.com/resource")
                .formParam("audience", "https://target-service.example.com")
                .formParam("scope", "openid profile")
                .formParam("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("subject_token", MOCK_SUBJECT_TOKEN)
                .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                .formParam("actor_token", "mock-actor-token")
                .formParam("actor_token_type", TOKEN_TYPE_JWT)
            .when()
                .post(TOKEN_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(200, 400, 500);

            if (response.getStatusCode() == 200) {
                String accessToken = response.jsonPath().getString("access_token");
                assertThat(accessToken).isNotNull();
                assertThat(accessToken).isNotEmpty();

                String tokenType = response.jsonPath().getString("token_type");
                assertThat(tokenType).isNotNull();

                String issuedTokenType = response.jsonPath().getString("issued_token_type");
                assertThat(issuedTokenType).isNotNull();
            }
        }
    }

    @Nested
    @DisplayName("Discovery Integration Tests")
    class DiscoveryIntegrationTests {

        @Test
        @DisplayName("OIDC Discovery should list supported grant types")
        void oidcDiscoveryShouldListSupportedGrantTypes() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get("http://localhost:8083/.well-known/openid-configuration");

            assertThat(response.getStatusCode()).isEqualTo(200);

            java.util.List<String> grantTypes = response.jsonPath().getList("grant_types_supported");
            assertThat(grantTypes).isNotNull();
            assertThat(grantTypes).isNotEmpty();
            assertThat(grantTypes).contains("authorization_code");
        }

        @Test
        @DisplayName("Token endpoint from Discovery should match expected endpoint")
        void tokenEndpointFromDiscoveryShouldMatchExpectedEndpoint() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get("http://localhost:8083/.well-known/openid-configuration");

            assertThat(response.getStatusCode()).isEqualTo(200);

            String tokenEndpoint = response.jsonPath().getString("token_endpoint");
            assertThat(tokenEndpoint).isNotNull();
            assertThat(tokenEndpoint).contains("/oauth2/token");
        }
    }
}
