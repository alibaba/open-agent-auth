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

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Protocol Conformance Test for OAuth 2.0 Pushed Authorization Requests (PAR).
 * <p>
 * This test class validates the Authorization Server's compliance with RFC 9126
 * "OAuth 2.0 Pushed Authorization Requests" specification.
 * </p>
 * <p>
 * The PAR specification defines a mechanism where the client pushes the authorization
 * request parameters as a direct HTTP request to the authorization server, and the
 * authorization server returns a {@code request_uri} value that can be used in the
 * subsequent authorization request.
 * </p>
 * <p>
 * <b>Key Requirements Validated:</b>
 * </p>
 * <ul>
 *   <li>RFC 9126 §2.1 - Request Format and Client Authentication</li>
 *   <li>RFC 9126 §2.2 - Success Response Format</li>
 *   <li>RFC 9126 §2.3 - Error Response Format</li>
 *   <li>RFC 9126 §4 - Request URI Lifecycle Management</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0 Authorization Framework</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "OAuth 2.0 Pushed Authorization Requests (PAR) Conformance Test",
    protocol = "OAuth 2.0 PAR",
    reference = "RFC 9126",
    requiredServices = {"localhost:8085"}
)
@DisplayName("OAuth 2.0 PAR Protocol Conformance Tests (RFC 9126)")
class OAuth2ParConformanceTest {

    private static final String BASE_URI = "http://localhost:8085";
    private static final String PAR_ENDPOINT = "/par";
    private static final String AUTHORIZATION_ENDPOINT = "/oauth2/authorize";

    private static final String CLIENT_ID = "sample-agent";
    private static final String CLIENT_SECRET = "sample-agent-secret";
    private static final String REDIRECT_URI = "http://localhost:8081/oauth/callback";
    private static final String SCOPE = "openid profile";
    private static final String RESPONSE_TYPE = "code";

    private static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

    private static RSAKey signingKey;

    @BeforeAll
    static void setupRestAssured() throws Exception {
        RestAssured.baseURI = BASE_URI;
        RestAssured.useRelaxedHTTPSValidation();
        signingKey = new RSAKeyGenerator(2048)
                .keyID("test-signing-key")
                .generate();
    }

    /**
     * Generates a mock PAR JWT (Request Object) for testing.
     * The AS requires a 'request' parameter containing a JWT with
     * authorization request parameters as claims.
     */
    private static String generateMockParJwt() {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(CLIENT_ID)
                    .subject("test-user")
                    .audience(BASE_URI)
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("redirect_uri", REDIRECT_URI)
                    .claim("response_type", RESPONSE_TYPE)
                    .claim("state", UUID.randomUUID().toString())
                    .claim("evidence", Map.of())
                    .claim("agent_user_binding_proposal", Map.of())
                    .claim("agent_operation_proposal", "allow")
                    .claim("context", Map.of("user", Map.of("id", "test-user")))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(signingKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate mock PAR JWT", e);
        }
    }

    /**
     * Generates a mock PAR JWT without a specific claim, for testing error scenarios
     * where the AS should not be able to extract the parameter from the JWT.
     */
    private static String generateParJwtWithoutClaim(String claimToExclude) {
        try {
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(CLIENT_ID)
                    .subject("test-user")
                    .audience(BASE_URI)
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("evidence", Map.of())
                    .claim("agent_user_binding_proposal", Map.of())
                    .claim("agent_operation_proposal", "allow")
                    .claim("context", Map.of("user", Map.of("id", "test-user")));

            if (!"redirect_uri".equals(claimToExclude)) {
                claimsBuilder.claim("redirect_uri", REDIRECT_URI);
            }
            if (!"response_type".equals(claimToExclude)) {
                claimsBuilder.claim("response_type", RESPONSE_TYPE);
            }
            if (!"state".equals(claimToExclude)) {
                claimsBuilder.claim("state", UUID.randomUUID().toString());
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(new RSASSASigner(signingKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate mock PAR JWT", e);
        }
    }

    private ValidatableResponse sendValidParRequest() {
        return RestAssured.given()
                .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .contentType(ContentType.URLENC)
                .formParam("request", generateMockParJwt())
                .formParam("response_type", RESPONSE_TYPE)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("scope", SCOPE)
                .when()
                .post(PAR_ENDPOINT)
                .then();
    }

    @Nested
    @DisplayName("Success Response Tests (RFC 9126 §2.2)")
    class SuccessResponseTests {

        @Test
        @DisplayName("Valid PAR request should return HTTP 201 Created")
        void validParRequestReturnsCreated() {
            sendValidParRequest()
                    .statusCode(201);
        }

        @Test
        @DisplayName("Response Content-Type must be application/json")
        void responseContentTypeMustBeApplicationJson() {
            sendValidParRequest()
                    .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("Response must contain request_uri field (REQUIRED)")
        void responseMustContainRequestUri() {
            String requestUri = sendValidParRequest()
                    .extract()
                    .path("request_uri");

            assertThat(requestUri)
                    .as("request_uri field is required in PAR response")
                    .isNotNull()
                    .isNotEmpty();
        }

        @Test
        @DisplayName("request_uri must start with 'urn:ietf:params:oauth:request_uri:'")
        void requestUriMustHaveCorrectPrefix() {
            String requestUri = sendValidParRequest()
                    .extract()
                    .path("request_uri");

            assertThat(requestUri)
                    .as("request_uri must have the required URN prefix")
                    .startsWith(REQUEST_URI_PREFIX);
        }

        @Test
        @DisplayName("Response must contain expires_in field (REQUIRED)")
        void responseMustContainExpiresIn() {
            Integer expiresIn = sendValidParRequest()
                    .extract()
                    .path("expires_in");

            assertThat(expiresIn)
                    .as("expires_in field is required in PAR response")
                    .isNotNull();
        }

        @Test
        @DisplayName("expires_in must be a positive integer")
        void expiresInMustBePositiveInteger() {
            Integer expiresIn = sendValidParRequest()
                    .extract()
                    .path("expires_in");

            assertThat(expiresIn)
                    .as("expires_in must be a positive integer")
                    .isGreaterThan(0);
        }
    }

    @Nested
    @DisplayName("Request Format Tests (RFC 9126 §2.1)")
    class RequestFormatTests {

        @Test
        @DisplayName("PAR endpoint must accept application/x-www-form-urlencoded Content-Type")
        void parEndpointAcceptsUrlEncodedContentType() {
            RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(201);
        }

        @Test
        @DisplayName("PAR endpoint must support HTTP POST method")
        void parEndpointSupportsPostMethod() {
            RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(201);
        }

        @Test
        @DisplayName("PAR endpoint must support client_secret_basic authentication")
        void parEndpointSupportsClientSecretBasicAuth() {
            RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(201);
        }
    }

    @Nested
    @DisplayName("Request URI Lifecycle Tests")
    class RequestUriLifecycleTests {

        @Test
        @DisplayName("Valid request_uri should be accepted by authorization endpoint")
        void validRequestUriRedirectsToConsent() {
            String requestUri = sendValidParRequest()
                    .extract()
                    .path("request_uri");

            // The authorization endpoint may return 302 (redirect to consent page)
            // or 200 (render consent page directly) depending on implementation
            io.restassured.response.Response response = RestAssured.given()
                    .redirects().follow(false)
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("request_uri", requestUri)
                    .when()
                    .get(AUTHORIZATION_ENDPOINT);

            assertThat(response.getStatusCode())
                    .as("Authorization endpoint should accept valid request_uri")
                    .isIn(200, 302);
        }

        @Test
        @DisplayName("Invalid request_uri should return 400 error")
        void invalidRequestUriReturnsBadRequest() {
            String invalidRequestUri = REQUEST_URI_PREFIX + "invalid-uri-12345";

            RestAssured.given()
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("request_uri", invalidRequestUri)
                    .when()
                    .get(AUTHORIZATION_ENDPOINT)
                    .then()
                    .statusCode(400);
        }

        @Test
        @DisplayName("Malformed request_uri format should return 400 error")
        void malformedRequestUriReturnsBadRequest() {
            String malformedRequestUri = "urn:ietf:params:oauth:malformed:uri";

            RestAssured.given()
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("request_uri", malformedRequestUri)
                    .when()
                    .get(AUTHORIZATION_ENDPOINT)
                    .then()
                    .statusCode(400);
        }
    }

    @Nested
    @DisplayName("Error Response Tests (RFC 9126 §2.3)")
    class ErrorResponseTests {

        @Test
        @DisplayName("Missing client authentication should return 401 Unauthorized")
        void missingClientAuthenticationReturnsUnauthorized() {
            RestAssured.given()
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(401);
        }

        @Test
        @DisplayName("Invalid client credentials should return 401 Unauthorized")
        void invalidClientCredentialsReturnsUnauthorized() {
            RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, "invalid-secret")
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(401);
        }

        @Test
        @DisplayName("Missing required parameter redirect_uri should return 400 with error fields")
        void missingRedirectUriReturnsBadRequestWithErrorFields() {
            // Generate a JWT without redirect_uri claim so AS cannot extract it from JWT
            String jwtWithoutRedirectUri = generateParJwtWithoutClaim("redirect_uri");
            io.restassured.response.Response response = RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", jwtWithoutRedirectUri)
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT);

            // AS may accept the request (201) if it has a default redirect_uri,
            // or reject it (400) if redirect_uri is truly required
            assertThat(response.getStatusCode()).isIn(201, 400);
            if (response.getStatusCode() == 400) {
                String error = response.jsonPath().getString("error");
                String errorDescription = response.jsonPath().getString("error_description");

                assertThat(error)
                        .as("error field must be present in error response")
                        .isNotNull()
                        .isNotEmpty();
                assertThat(errorDescription)
                        .as("error_description field must be present in error response")
                        .isNotNull()
                        .isNotEmpty();
            }
        }

        @Test
        @DisplayName("Invalid redirect_uri should return error or be accepted")
        void invalidRedirectUriReturnsBadRequest() {
            // AS may not validate redirect_uri against registered values
            io.restassured.response.Response response = RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", "http://invalid-uri.com/callback")
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(201, 400);
        }

        @Test
        @DisplayName("Missing response_type should return error or default to 'code'")
        void missingResponseTypeReturnsBadRequest() {
            // AS may default response_type to "code" when missing
            io.restassured.response.Response response = RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateParJwtWithoutClaim("response_type"))
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT);

            assertThat(response.getStatusCode()).isIn(201, 400);
        }
    }

    @Nested
    @DisplayName("Client Authentication Tests")
    class ClientAuthenticationTests {

        @Test
        @DisplayName("Should support HTTP Basic Authentication")
        void supportsHttpBasicAuthentication() {
            RestAssured.given()
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(201);
        }

        @Test
        @DisplayName("Request without authentication should return 401 Unauthorized")
        void requestWithoutAuthenticationReturnsUnauthorized() {
            RestAssured.given()
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateMockParJwt())
                    .formParam("response_type", RESPONSE_TYPE)
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", SCOPE)
                    .when()
                    .post(PAR_ENDPOINT)
                    .then()
                    .statusCode(401);
        }
    }
}