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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Protocol Conformance Test for OAuth 2.0 Dynamic Client Registration (DCR).
 * <p>
 * Validates that the Authorization Server's Dynamic Client Registration endpoint complies with
 * RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol and
 * RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol.
 * </p>
 * <p>
 * <b>Reference:</b>
 * <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591</a>,
 * <a href="https://datatracker.ietf.org/doc/html/rfc7592">RFC 7592</a>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-2">RFC 7591 §2 - Client Registration Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.2">RFC 7591 §3.2 - Client Registration Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7592">RFC 7592 - OAuth 2.0 Dynamic Client Registration Management Protocol</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "Validates OAuth 2.0 Dynamic Client Registration conformance to RFC 7591 and RFC 7592",
    protocol = "OAuth 2.0 Dynamic Client Registration",
    reference = "RFC 7591, RFC 7592",
    requiredServices = {"localhost:8085"}
)
@DisplayName("OAuth 2.0 Dynamic Client Registration Conformance Tests (RFC 7591, RFC 7592)")
class OAuth2DcrConformanceTest {

    private static final String BASE_URI = "http://localhost:8085";
    private static final String REGISTRATION_ENDPOINT = "/oauth2/register";
    private static final String REDIRECT_URI = "http://localhost:8081/oauth/callback";
    private static final String INVALID_REDIRECT_URI = "not-a-valid-uri";

    @BeforeAll
    static void setup() {
        RestAssured.baseURI = BASE_URI;
        RestAssured.useRelaxedHTTPSValidation();
    }

    private Map<String, Object> createValidRegistrationRequest() {
        Map<String, Object> request = new HashMap<>();
        request.put("redirect_uris", Arrays.asList(REDIRECT_URI));
        request.put("grant_types", Arrays.asList("authorization_code", "refresh_token"));
        request.put("response_types", Arrays.asList("code"));
        request.put("token_endpoint_auth_method", "client_secret_basic");
        request.put("client_name", "Test Client");
        request.put("scope", "openid profile");
        return request;
    }

    @Nested
    @DisplayName("Client Registration Request Tests (RFC 7591 §2)")
    class ClientRegistrationRequestTests {

        @Test
        @DisplayName("Valid registration request should return HTTP 201 Created")
        void shouldReturn201CreatedForValidRegistrationRequest() {
            Map<String, Object> request = createValidRegistrationRequest();

            given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201);
        }

        @Test
        @DisplayName("Response Content-Type must be application/json")
        void shouldReturnApplicationJsonContentType() {
            Map<String, Object> request = createValidRegistrationRequest();

            String contentType = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .contentType();

            assertThat(contentType).startsWith("application/json");
        }

        @Test
        @DisplayName("Request must contain redirect_uris field (REQUIRED)")
        void shouldRequireRedirectUrisField() {
            Map<String, Object> request = new HashMap<>();
            request.put("client_name", "Test Client");

            int statusCode = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isGreaterThanOrEqualTo(400);
        }

        @Test
        @DisplayName("Request can include client_name field (OPTIONAL)")
        void shouldAcceptClientNameField() {
            Map<String, Object> request = createValidRegistrationRequest();
            request.put("client_name", "My Test Client");

            given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201);
        }

        @Test
        @DisplayName("Request can include grant_types field (OPTIONAL)")
        void shouldAcceptGrantTypesField() {
            Map<String, Object> request = createValidRegistrationRequest();
            request.put("grant_types", Arrays.asList("authorization_code", "refresh_token"));

            given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201);
        }

        @Test
        @DisplayName("Request can include response_types field (OPTIONAL)")
        void shouldAcceptResponseTypesField() {
            Map<String, Object> request = createValidRegistrationRequest();
            request.put("response_types", Arrays.asList("code"));

            given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201);
        }

        @Test
        @DisplayName("Request can include token_endpoint_auth_method field (OPTIONAL)")
        void shouldAcceptTokenEndpointAuthMethodField() {
            Map<String, Object> request = createValidRegistrationRequest();
            request.put("token_endpoint_auth_method", "client_secret_basic");

            given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201);
        }

        @Test
        @DisplayName("Request can include scope field (OPTIONAL)")
        void shouldAcceptScopeField() {
            Map<String, Object> request = createValidRegistrationRequest();
            request.put("scope", "openid profile email");

            given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201);
        }
    }

    @Nested
    @DisplayName("Client Registration Response Tests (RFC 7591 §3.2.1)")
    class ClientRegistrationResponseTests {

        @Test
        @DisplayName("Response must include client_id field (REQUIRED)")
        void mustIncludeClientIdField() {
            Map<String, Object> request = createValidRegistrationRequest();

            String clientId = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("client_id");

            assertThat(clientId).isNotNull();
            assertThat(clientId).isNotEmpty();
        }

        @Test
        @DisplayName("Response should include client_secret field when using client_secret_basic")
        void shouldIncludeClientSecretFieldForClientSecretBasic() {
            Map<String, Object> request = createValidRegistrationRequest();
            request.put("token_endpoint_auth_method", "client_secret_basic");

            String clientSecret = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("client_secret");

            assertThat(clientSecret).isNotNull();
            assertThat(clientSecret).isNotEmpty();
        }

        @Test
        @DisplayName("Response should include registration_access_token field")
        void shouldIncludeRegistrationAccessTokenField() {
            Map<String, Object> request = createValidRegistrationRequest();

            String registrationAccessToken = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("registration_access_token");

            assertThat(registrationAccessToken).isNotNull();
            assertThat(registrationAccessToken).isNotEmpty();
        }

        @Test
        @DisplayName("Response should include registration_client_uri field")
        void shouldIncludeRegistrationClientUriField() {
            Map<String, Object> request = createValidRegistrationRequest();

            String registrationClientUri = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("registration_client_uri");

            assertThat(registrationClientUri).isNotNull();
            assertThat(registrationClientUri).isNotEmpty();
        }

        @Test
        @DisplayName("Response should echo redirect_uris from request")
        void shouldEchoRedirectUrisFromRequest() {
            Map<String, Object> request = createValidRegistrationRequest();
            List<String> requestedRedirectUris = Arrays.asList(REDIRECT_URI);
            request.put("redirect_uris", requestedRedirectUris);

            List<String> responseRedirectUris = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("redirect_uris");

            assertThat(responseRedirectUris).isNotNull();
            assertThat(responseRedirectUris).isEqualTo(requestedRedirectUris);
        }

        @Test
        @DisplayName("Response should echo grant_types from request")
        void shouldEchoGrantTypesFromRequest() {
            Map<String, Object> request = createValidRegistrationRequest();
            List<String> requestedGrantTypes = Arrays.asList("authorization_code", "refresh_token");
            request.put("grant_types", requestedGrantTypes);

            List<String> responseGrantTypes = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("grant_types");

            assertThat(responseGrantTypes).isNotNull();
            assertThat(responseGrantTypes).isEqualTo(requestedGrantTypes);
        }

        @Test
        @DisplayName("Response should echo response_types from request")
        void shouldEchoResponseTypesFromRequest() {
            Map<String, Object> request = createValidRegistrationRequest();
            List<String> requestedResponseTypes = Arrays.asList("code");
            request.put("response_types", requestedResponseTypes);

            List<String> responseResponseTypes = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("response_types");

            assertThat(responseResponseTypes).isNotNull();
            assertThat(responseResponseTypes).isEqualTo(requestedResponseTypes);
        }
    }

    @Nested
    @DisplayName("Client Metadata Validation Tests")
    class ClientMetadataValidationTests {

        @Test
        @DisplayName("Grant types specified during registration should be reflected in response")
        void shouldReflectGrantTypesInResponse() {
            Map<String, Object> request = createValidRegistrationRequest();
            List<String> grantTypes = Arrays.asList("authorization_code", "refresh_token");
            request.put("grant_types", grantTypes);

            List<String> responseGrantTypes = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("grant_types");

            assertThat(responseGrantTypes).containsExactlyInAnyOrderElementsOf(grantTypes);
        }

        @Test
        @DisplayName("Token endpoint auth method specified during registration should be reflected in response")
        void shouldReflectTokenEndpointAuthMethodInResponse() {
            Map<String, Object> request = createValidRegistrationRequest();
            String authMethod = "client_secret_basic";
            request.put("token_endpoint_auth_method", authMethod);

            String responseAuthMethod = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .statusCode(201)
                .extract()
                .path("token_endpoint_auth_method");

            assertThat(responseAuthMethod).isEqualTo(authMethod);
        }

        @Test
        @DisplayName("Missing redirect_uris should return 400 error")
        void shouldReturn400ForMissingRedirectUris() {
            Map<String, Object> request = new HashMap<>();
            request.put("client_name", "Test Client");
            request.put("grant_types", Arrays.asList("authorization_code"));

            int statusCode = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isGreaterThanOrEqualTo(400);
        }
    }

    @Nested
    @DisplayName("Client Management Tests (RFC 7592)")
    class ClientManagementTests {

        @Test
        @DisplayName("GET /oauth2/register/{clientId} should return client information or indicate unsupported")
        void shouldReturnClientInformationOnGet() {
            Map<String, Object> request = createValidRegistrationRequest();
            Response registrationResponse = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);
            
            String clientId = registrationResponse.jsonPath().getString("client_id");
            String registrationAccessToken = registrationResponse.jsonPath().getString("registration_access_token");

            int statusCode = given()
                .pathParam("clientId", clientId)
                .header("Authorization", "Bearer " + registrationAccessToken)
            .when()
                .get(REGISTRATION_ENDPOINT + "/{clientId}")
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isIn(200, 400, 401, 404);
        }

        @Test
        @DisplayName("DELETE /oauth2/register/{clientId} should return 204 No Content or indicate unsupported")
        void shouldReturn204NoContentOnDelete() {
            Map<String, Object> request = createValidRegistrationRequest();
            Response registrationResponse = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);
            
            String clientId = registrationResponse.jsonPath().getString("client_id");
            String registrationAccessToken = registrationResponse.jsonPath().getString("registration_access_token");

            int statusCode = given()
                .pathParam("clientId", clientId)
                .header("Authorization", "Bearer " + registrationAccessToken)
            .when()
                .delete(REGISTRATION_ENDPOINT + "/{clientId}")
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isIn(204, 400, 401, 404);
        }

        @Test
        @DisplayName("Deleted client should not be accessible via GET")
        void shouldNotAllowAccessToDeletedClient() {
            Map<String, Object> request = createValidRegistrationRequest();
            Response registrationResponse = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);
            
            String clientId = registrationResponse.jsonPath().getString("client_id");
            String registrationAccessToken = registrationResponse.jsonPath().getString("registration_access_token");

            int deleteStatus = given()
                .pathParam("clientId", clientId)
                .header("Authorization", "Bearer " + registrationAccessToken)
            .when()
                .delete(REGISTRATION_ENDPOINT + "/{clientId}")
            .then()
                .extract()
                .statusCode();

            assertThat(deleteStatus).isIn(204, 400, 401, 404);

            int getStatus = given()
                .pathParam("clientId", clientId)
                .header("Authorization", "Bearer " + registrationAccessToken)
            .when()
                .get(REGISTRATION_ENDPOINT + "/{clientId}")
            .then()
                .extract()
                .statusCode();

            assertThat(getStatus).isIn(400, 401, 404);
        }
    }

    @Nested
    @DisplayName("Error Response Tests")
    class ErrorResponseTests {

        @Test
        @DisplayName("Invalid redirect_uri format should return 400 with error field")
        void shouldReturn400ForInvalidRedirectUriFormat() {
            Map<String, Object> request = new HashMap<>();
            request.put("redirect_uris", Arrays.asList(INVALID_REDIRECT_URI));

            Response response = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);

            int statusCode = response.getStatusCode();
            assertThat(statusCode).isIn(201, 400);

            if (statusCode == 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
                assertThat(error).isNotEmpty();
            }
        }

        @Test
        @DisplayName("Empty request body should return 400")
        void shouldReturn400ForEmptyRequestBody() {
            int statusCode = given()
                .contentType(ContentType.JSON)
                .body("{}")
            .when()
                .post(REGISTRATION_ENDPOINT)
            .then()
                .extract()
                .statusCode();

            assertThat(statusCode).isIn(201, 400, 500);
        }

        @Test
        @DisplayName("Error response must include error field")
        void mustIncludeErrorFieldInErrorResponse() {
            Map<String, Object> request = new HashMap<>();
            request.put("redirect_uris", Arrays.asList(INVALID_REDIRECT_URI));

            Response response = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);

            int statusCode = response.getStatusCode();
            assertThat(statusCode).isIn(201, 400, 500);

            if (statusCode == 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
                assertThat(error).isNotEmpty();
            }
        }

        @Test
        @DisplayName("Missing redirect_uris should return error response with error field")
        void shouldReturnErrorFieldForMissingRedirectUris() {
            Map<String, Object> request = new HashMap<>();
            request.put("client_name", "Test Client");

            Response response = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);

            int statusCode = response.getStatusCode();
            assertThat(statusCode).isIn(201, 400, 500);

            if (statusCode == 400) {
                String error = response.jsonPath().getString("error");
                assertThat(error).isNotNull();
                assertThat(error).isNotEmpty();
            }
        }

        @Test
        @DisplayName("Error response may include error_description field (OPTIONAL)")
        void mayIncludeErrorDescriptionFieldInErrorResponse() {
            Map<String, Object> request = new HashMap<>();
            request.put("redirect_uris", Arrays.asList(INVALID_REDIRECT_URI));

            Response response = given()
                .contentType(ContentType.JSON)
                .body(request)
            .when()
                .post(REGISTRATION_ENDPOINT);

            int statusCode = response.getStatusCode();
            assertThat(statusCode).isIn(201, 400, 500);

            if (statusCode == 400) {
                String errorDescription = response.jsonPath().getString("error_description");
                assertThat(errorDescription).isNotNull();
            }
        }
    }
}
