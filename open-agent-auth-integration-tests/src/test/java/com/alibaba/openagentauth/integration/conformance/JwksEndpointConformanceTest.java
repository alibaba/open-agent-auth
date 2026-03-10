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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

/**
 * Protocol conformance tests for JWKS (JSON Web Key Set) endpoint.
 * <p>
 * This test class validates that the JWKS endpoints of various services conform to
 * RFC 7517 (JSON Web Key (JWK)) specification, particularly Section 5 which defines
 * the JWK Set (JWKS) JSON representation.
 * </p>
 * <p>
 * Tests verify:
 * </p>
 * <ul>
 *   <li>JWK Set format compliance per RFC 7517 §5</li>
 *   <li>Required JWK fields (kty, kid) per RFC 7517 §4.1</li>
 *   <li>RSA key parameter requirements (n, e)</li>
 *   <li>Key algorithm and usage validation</li>
 *   <li>Multi-service JWKS endpoint accessibility</li>
 *   <li>Caching behavior for JWKS responses</li>
 *   <li>Security: no private key material exposure</li>
 * </ul>
 * <p>
 * <b>Note:</b> These tests require the following services to be running:
 * </p>
 * <ul>
 *   <li>Authorization Server (localhost:8085)</li>
 *   <li>Agent User IDP (localhost:8083)</li>
 *   <li>AS User IDP (localhost:8084)</li>
 *   <li>Agent IDP (localhost:8082)</li>
 * </ul>
 * <p>
 * Use the provided scripts to start the services before running tests:
 * <pre>
 *   cd open-agent-auth-samples
 *   ./scripts/sample-start.sh
 * </pre>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-5">RFC 7517 §5 - JWK Set Format</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4">RFC 7517 §4 - JWK Parameters</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "JWKS Endpoint Conformance Tests",
    protocol = "JWKS (RFC 7517)",
    reference = "RFC 7517 §5, §4.1",
    requiredServices = {"localhost:8082", "localhost:8083", "localhost:8084", "localhost:8085"}
)
@DisplayName("JWKS Endpoint Conformance Tests")
class JwksEndpointConformanceTest {

    private static final String AS_BASE_URI = "http://localhost:8085";
    private static final String AGENT_USER_IDP_BASE_URI = "http://localhost:8083";
    private static final String AS_USER_IDP_BASE_URI = "http://localhost:8084";
    private static final String AGENT_IDP_BASE_URI = "http://localhost:8082";
    private static final String JWKS_PATH = "/.well-known/jwks.json";

    private static final Set<String> PRIVATE_KEY_FIELDS = Set.of("d", "p", "q", "dp", "dq", "qi");
    private static final Set<String> VALID_KEY_TYPES = Set.of("RSA", "EC");
    private static final Set<String> VALID_KEY_USE = Set.of("sig", "enc");
    private static final Set<String> VALID_JWS_ALGORITHMS = Set.of(
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
        "ES256K", "EdDSA"
    );

    @BeforeEach
    void setUp() {
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    }

    @Nested
    @DisplayName("JWK Set Format Tests - RFC 7517 §5")
    class JwkSetFormatTests {

        @Test
        @DisplayName("AS JWKS endpoint should return JSON content type")
        void asJwksEndpointShouldReturnJsonContentType() {
            given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("JWKS response must contain keys array field")
        void jwksResponseMustContainKeysArrayField() {
            given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .body("$", hasKey("keys"))
                .body("keys", instanceOf(List.class));
        }

        @Test
        @DisplayName("keys array must not be empty")
        void keysArrayMustNotBeEmpty() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();
            assertThat(keys).isNotEmpty();
        }

        @Test
        @DisplayName("Each JWK must contain kty field (REQUIRED per RFC 7517 §4.1)")
        void eachJwkMustContainKtyField() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();
            assertThat(keys).allMatch(key -> key.containsKey("kty"));
        }

        @Test
        @DisplayName("Each JWK must contain kid field for key identification")
        void eachJwkMustContainKidField() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();
            assertThat(keys).allMatch(key -> key.containsKey("kid"));
        }

        @Test
        @DisplayName("RSA keys must contain n and e fields")
        void rsaKeysMustContainNAndEFields() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();

            keys.stream()
                .filter(key -> "RSA".equals(key.get("kty")))
                .forEach(rsaKey -> {
                    assertThat(rsaKey).containsKey("n");
                    assertThat(rsaKey).containsKey("e");
                    assertThat(rsaKey.get("n")).isInstanceOf(String.class);
                    assertThat(rsaKey.get("e")).isInstanceOf(String.class);
                });
        }

        @Test
        @DisplayName("JWK must not contain private key fields")
        void jwkMustNotContainPrivateKeyFields() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();

            keys.forEach(key -> {
                PRIVATE_KEY_FIELDS.forEach(privateField -> {
                    assertThat(key).doesNotContainKey(privateField);
                });
            });
        }
    }

    @Nested
    @DisplayName("Key Algorithm Tests")
    class KeyAlgorithmTests {

        @Test
        @DisplayName("kty value must be registered type (RSA or EC)")
        void ktyValueMustBeRegisteredType() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();

            keys.forEach(key -> {
                String kty = (String) key.get("kty");
                assertThat(kty).isNotNull();
                assertThat(kty).isIn(VALID_KEY_TYPES);
            });
        }

        @Test
        @DisplayName("If alg field present, must be valid JWS algorithm")
        void ifAlgFieldPresentMustBeValidJwsAlgorithm() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();

            keys.stream()
                .filter(key -> key.containsKey("alg"))
                .forEach(key -> {
                    String alg = (String) key.get("alg");
                    assertThat(alg).isNotNull();
                    assertThat(alg).isIn(VALID_JWS_ALGORITHMS);
                });
        }

        @Test
        @DisplayName("If use field present, must be sig or enc")
        void ifUseFieldPresentMustBeSigOrEnc() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();

            keys.stream()
                .filter(key -> key.containsKey("use"))
                .forEach(key -> {
                    String use = (String) key.get("use");
                    assertThat(use).isNotNull();
                    assertThat(use).isIn(VALID_KEY_USE);
                });
        }
    }

    @Nested
    @DisplayName("Multi-Service JWKS Tests")
    class MultiServiceJwksTests {

        @Test
        @DisplayName("AS JWKS endpoint should be accessible")
        void asJwksEndpointShouldBeAccessible() {
            given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("Agent User IDP JWKS endpoint should be accessible")
        void agentUserIdpJwksEndpointShouldBeAccessible() {
            given()
                .baseUri(AGENT_USER_IDP_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("AS User IDP JWKS endpoint should be accessible")
        void asUserIdpJwksEndpointShouldBeAccessible() {
            given()
                .baseUri(AS_USER_IDP_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("Agent IDP JWKS endpoint should be accessible")
        void agentIdpJwksEndpointShouldBeAccessible() {
            given()
                .baseUri(AGENT_IDP_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .contentType(ContentType.JSON);
        }

        @Test
        @DisplayName("Each service should have unique kids in its JWKS")
        void eachServiceShouldHaveUniqueKidsInItsJwks() {
            String[] baseUris = {
                AS_BASE_URI,
                AGENT_USER_IDP_BASE_URI,
                AS_USER_IDP_BASE_URI,
                AGENT_IDP_BASE_URI
            };

            for (String baseUri : baseUris) {
                Response response = given()
                    .baseUri(baseUri)
                .when()
                    .get(JWKS_PATH);

                List<Map<String, Object>> keys = response.jsonPath().getList("keys");
                assertThat(keys).isNotNull();

                Set<String> kids = new HashSet<>();
                keys.forEach(key -> {
                    String kid = (String) key.get("kid");
                    assertThat(kid).isNotNull();
                    assertThat(kids).doesNotContain(kid);
                    kids.add(kid);
                });
            }
        }
    }

    @Nested
    @DisplayName("Caching Behavior Tests")
    class CachingBehaviorTests {

        @Test
        @DisplayName("Response should include Cache-Control header")
        void responseShouldIncludeCacheControlHeader() {
            given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .header("Cache-Control", notNullValue());
        }

        @Test
        @DisplayName("Cache-Control should include max-age directive")
        void cacheControlShouldIncludeMaxAgeDirective() {
            given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH)
            .then()
                .statusCode(200)
                .header("Cache-Control", containsString("max-age"));
        }

        @Test
        @DisplayName("Consecutive requests should return same key set")
        void consecutiveRequestsShouldReturnSameKeySet() {
            Response firstResponse = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> firstKeys = firstResponse.jsonPath().getList("keys");

            Response secondResponse = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> secondKeys = secondResponse.jsonPath().getList("keys");

            assertThat(firstKeys).isNotNull();
            assertThat(secondKeys).isNotNull();
            assertThat(firstKeys).hasSameSizeAs(secondKeys);

            for (int i = 0; i < firstKeys.size(); i++) {
                assertThat(firstKeys.get(i).get("kid")).isEqualTo(secondKeys.get(i).get("kid"));
                assertThat(firstKeys.get(i).get("kty")).isEqualTo(secondKeys.get(i).get("kty"));
            }
        }
    }

    @Nested
    @DisplayName("Negative Tests")
    class NegativeTests {

        @Test
        @DisplayName("Request to non-existent JWKS path should return 404")
        void requestToNonExistentJwksPathShouldReturn404() {
            given()
                .baseUri(AS_BASE_URI)
            .when()
                .get("/.well-known/jwks-invalid.json")
            .then()
                .statusCode(404);
        }

        @Test
        @DisplayName("JWK should not contain private key material")
        void jwkShouldNotContainPrivateKeyMaterial() {
            Response response = given()
                .baseUri(AS_BASE_URI)
            .when()
                .get(JWKS_PATH);

            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotNull();

            keys.forEach(key -> {
                PRIVATE_KEY_FIELDS.forEach(privateField -> {
                    assertThat(key).doesNotContainKey(privateField);
                });
            });
        }
    }
}
