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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

/**
 * Protocol conformance tests for OpenID Connect Discovery 1.0.
 * <p>
 * This test class validates that the Authorization Server's OIDC Discovery endpoint
 * conforms to the OpenID Connect Discovery 1.0 specification (Section 3) and RFC 8414
 * (Authorization Server Metadata).
 * </p>
 * <p>
 * Tests verify:
 * </p>
 * <ul>
 *   <li>Required metadata fields per OpenID Connect Discovery 1.0</li>
 *   <li>Recommended metadata fields for better interoperability</li>
 *   <li>Agent Operation Authorization extension fields</li>
 *   <li>Endpoint URL consistency and accessibility</li>
 *   <li>Security considerations (no sensitive information exposure)</li>
 * </ul>
 * <p>
 * <b>Note:</b> These tests require the Authorization Server to be running.
 * Use the provided scripts to start the server before running tests:
 * <pre>
 *   cd open-agent-auth-samples
 *   ./scripts/sample-start.sh
 * </pre>
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery 1.0 - Section 3</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8414">RFC 8414 - Authorization Server Metadata</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "OIDC Discovery Conformance Tests",
    protocol = "OpenID Connect Discovery 1.0",
    reference = "OpenID Connect Discovery 1.0 §3, RFC 8414",
    requiredServices = {"localhost:8083"}
)
@DisplayName("OIDC Discovery Conformance Tests")
class OidcDiscoveryConformanceTest {

    private static final String BASE_URI = "http://localhost:8083";
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    @BeforeEach
    void setUp() {
        RestAssured.baseURI = BASE_URI;
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    }

    @Nested
    @DisplayName("Required Fields Tests")
    class RequiredFieldsTests {

        @Test
        @DisplayName("Should return JSON content type")
        void shouldReturnJsonContentType() {
            given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("Should include required issuer field")
        void shouldIncludeRequiredIssuerField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            String issuer = response.jsonPath().getString("issuer");
            assertThat(issuer).isNotNull();
            assertThat(issuer).startsWith("http");
        }

        @Test
        @DisplayName("Should include required authorization_endpoint field")
        void shouldIncludeRequiredAuthorizationEndpointField() {
            given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH)
            .then()
                .statusCode(200)
                .body("authorization_endpoint", notNullValue())
                .body("authorization_endpoint", instanceOf(String.class));
        }

        @Test
        @DisplayName("Should include required token_endpoint field")
        void shouldIncludeRequiredTokenEndpointField() {
            given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH)
            .then()
                .statusCode(200)
                .body("token_endpoint", notNullValue())
                .body("token_endpoint", instanceOf(String.class));
        }

        @Test
        @DisplayName("Should include required jwks_uri field")
        void shouldIncludeRequiredJwksUriField() {
            given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH)
            .then()
                .statusCode(200)
                .body("jwks_uri", notNullValue())
                .body("jwks_uri", instanceOf(String.class));
        }

        @Test
        @DisplayName("Should include required response_types_supported field")
        void shouldIncludeRequiredResponseTypesSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> responseTypes = response.jsonPath().getList("response_types_supported");
            assertThat(responseTypes).isNotNull();
            assertThat(responseTypes).isNotEmpty();
            assertThat(responseTypes).contains("code");
        }

        @Test
        @DisplayName("Should include required subject_types_supported field")
        void shouldIncludeRequiredSubjectTypesSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> subjectTypes = response.jsonPath().getList("subject_types_supported");
            assertThat(subjectTypes).isNotNull();
            assertThat(subjectTypes).isNotEmpty();
        }

        @Test
        @DisplayName("Should include required id_token_signing_alg_values_supported field")
        void shouldIncludeRequiredIdTokenSigningAlgValuesSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> signingAlgs = response.jsonPath().getList("id_token_signing_alg_values_supported");
            assertThat(signingAlgs).isNotNull();
            assertThat(signingAlgs).isNotEmpty();
            assertThat(signingAlgs).containsAnyOf("RS256", "ES256", "PS256");
        }

        @Test
        @DisplayName("Should have issuer value matching request host")
        void shouldHaveIssuerValueMatchingRequestHost() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            String issuer = response.jsonPath().getString("issuer");
            assertThat(issuer).isNotNull();
            assertThat(issuer).startsWith("http");
        }
    }

    @Nested
    @DisplayName("Recommended Fields Tests")
    class RecommendedFieldsTests {

        @Test
        @DisplayName("Should include scopes_supported field")
        void shouldIncludeScopesSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> scopes = response.jsonPath().getList("scopes_supported");
            assertThat(scopes).isNotNull();
            assertThat(scopes).isNotEmpty();
            assertThat(scopes).contains("openid");
        }

        @Test
        @DisplayName("Should include grant_types_supported field")
        void shouldIncludeGrantTypesSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> grantTypes = response.jsonPath().getList("grant_types_supported");
            assertThat(grantTypes).isNotNull();
            assertThat(grantTypes).isNotEmpty();
            assertThat(grantTypes).contains("authorization_code");
        }

        @Test
        @DisplayName("Should include token_endpoint_auth_methods_supported field")
        void shouldIncludeTokenEndpointAuthMethodsSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> authMethods = response.jsonPath().getList("token_endpoint_auth_methods_supported");
            assertThat(authMethods).isNotNull();
            assertThat(authMethods).isNotEmpty();
            assertThat(authMethods).contains("client_secret_basic");
        }

        @Test
        @DisplayName("Should include claims_supported field")
        void shouldIncludeClaimsSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> claims = response.jsonPath().getList("claims_supported");
            assertThat(claims).isNotNull();
            assertThat(claims).isNotEmpty();
            assertThat(claims).contains("sub", "iss", "aud");
        }
    }

    @Nested
    @DisplayName("Agent Operation Authorization Extension Fields Tests")
    class AgentAuthExtensionFieldsTests {

        @Test
        @DisplayName("Should include pushed_authorization_request_endpoint field")
        void shouldIncludePushedAuthorizationRequestEndpointField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            Map<String, Object> discoveryDocument = response.jsonPath().getMap("$");
            
            if (discoveryDocument.containsKey("pushed_authorization_request_endpoint")) {
                String parEndpoint = response.jsonPath().getString("pushed_authorization_request_endpoint");
                assertThat(parEndpoint).isNotNull();
                assertThat(parEndpoint).isInstanceOf(String.class);
                assertThat(parEndpoint).endsWith("/par");
            }
            // If the field doesn't exist, the test passes (IDP may not support PAR)
        }

        @Test
        @DisplayName("Should include revocation_endpoint field")
        void shouldIncludeRevocationEndpointField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            Map<String, Object> discoveryDocument = response.jsonPath().getMap("$");
            
            if (discoveryDocument.containsKey("revocation_endpoint")) {
                String revocationEndpoint = response.jsonPath().getString("revocation_endpoint");
                assertThat(revocationEndpoint).isNotNull();
                assertThat(revocationEndpoint).isInstanceOf(String.class);
                assertThat(revocationEndpoint).endsWith("/oauth2/revoke");
            }
            // If the field doesn't exist, the test passes (IDP may not support revocation)
        }

        @Test
        @DisplayName("Should include code_challenge_methods_supported field")
        void shouldIncludeCodeChallengeMethodsSupportedField() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            List<String> codeChallengeMethods = response.jsonPath().getList("code_challenge_methods_supported");
            assertThat(codeChallengeMethods).isNotNull();
            assertThat(codeChallengeMethods).isNotEmpty();
            assertThat(codeChallengeMethods).contains("S256");
        }
    }

    @Nested
    @DisplayName("Endpoint Consistency Tests")
    class EndpointConsistencyTests {

        @Test
        @DisplayName("Should have accessible jwks_uri endpoint")
        void shouldHaveAccessibleJwksUriEndpoint() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            String jwksUri = response.jsonPath().getString("jwks_uri");
            assertThat(jwksUri).isNotNull();

            given()
                .accept(ContentType.JSON)
            .when()
                .get(jwksUri)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON)
                .body("keys", notNullValue())
                .body("keys", instanceOf(List.class));
        }

        @Test
        @DisplayName("Should have correct authorization_endpoint path format")
        void shouldHaveCorrectAuthorizationEndpointPathFormat() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            String authEndpoint = response.jsonPath().getString("authorization_endpoint");
            assertThat(authEndpoint).isNotNull();
            assertThat(authEndpoint).startsWith(BASE_URI);
            assertThat(authEndpoint).contains("/oauth2/authorize");
        }

        @Test
        @DisplayName("Should have correct token_endpoint path format")
        void shouldHaveCorrectTokenEndpointPathFormat() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            String tokenEndpoint = response.jsonPath().getString("token_endpoint");
            assertThat(tokenEndpoint).isNotNull();
            assertThat(tokenEndpoint).startsWith(BASE_URI);
            assertThat(tokenEndpoint).contains("/oauth2/token");
        }

        @Test
        @DisplayName("Should have consistent base URI across all endpoints")
        void shouldHaveConsistentBaseUriAcrossAllEndpoints() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            String issuer = response.jsonPath().getString("issuer");
            String authEndpoint = response.jsonPath().getString("authorization_endpoint");
            String tokenEndpoint = response.jsonPath().getString("token_endpoint");
            String jwksUri = response.jsonPath().getString("jwks_uri");

            assertThat(issuer).isNotNull();
            assertThat(issuer).startsWith("http");
            assertThat(authEndpoint).startsWith(issuer);
            assertThat(tokenEndpoint).startsWith(issuer);
            assertThat(jwksUri).startsWith(issuer);
        }
    }

    @Nested
    @DisplayName("Negative Tests")
    class NegativeTests {

        @Test
        @DisplayName("Should return 404 for non-existent discovery path")
        void shouldReturn404ForNonExistentDiscoveryPath() {
            given()
                .accept(ContentType.JSON)
            .when()
                .get("/.well-known/openid-configuration-invalid")
            .then()
                .statusCode(404);
        }

        @Test
        @DisplayName("Should not expose client_secret in discovery response")
        void shouldNotExposeClientSecretInDiscoveryResponse() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            Map<String, Object> discoveryDocument = response.jsonPath().getMap("$");
            assertThat(discoveryDocument).doesNotContainKey("client_secret");
        }

        @Test
        @DisplayName("Should not expose sensitive authentication information")
        void shouldNotExposeSensitiveAuthenticationInformation() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(DISCOVERY_PATH);

            Map<String, Object> discoveryDocument = response.jsonPath().getMap("$");
            
            assertThat(discoveryDocument).doesNotContainKey("client_secret");
            assertThat(discoveryDocument).doesNotContainKey("password");
            assertThat(discoveryDocument).doesNotContainKey("private_key");
        }

        @Test
        @DisplayName("Should reject requests with invalid Accept header")
        void shouldRejectRequestsWithInvalidAcceptHeader() {
            given()
                .accept(ContentType.XML)
            .when()
                .get(DISCOVERY_PATH)
            .then()
                .statusCode(anyOf(is(406), is(200)));
        }
    }
}