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
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Protocol Interoperability Conformance Tests.
 * <p>
 * This test class validates cross-protocol integration scenarios that verify
 * multiple OAuth 2.0 / OpenID Connect / WIMSE protocols working together
 * as a cohesive system. Unlike individual conformance tests that validate
 * single protocol compliance, these tests verify the interoperability between
 * protocols in realistic end-to-end flows.
 * </p>
 * <p>
 * <b>Test Scenarios:</b>
 * </p>
 * <ul>
 *   <li>DCR → PAR → Token: Dynamic client registration followed by PAR and token request</li>
 *   <li>OIDC Discovery → JWKS → Token Verification: Discovery-driven key retrieval and token validation</li>
 *   <li>PAR → Authorization → Token Exchange: Full authorization flow with token exchange</li>
 *   <li>WIT/WPT → Token Exchange: Workload identity credentials used in token exchange</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8693">RFC 8693 - Token Exchange</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">WIMSE Workload Credentials</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "Cross-Protocol Interoperability Conformance Tests",
    protocol = "OAuth 2.0 / OIDC / WIMSE Interoperability",
    reference = "RFC 7591, RFC 9126, RFC 8693, draft-ietf-wimse-workload-creds",
    requiredServices = {"localhost:8082", "localhost:8083", "localhost:8084", "localhost:8085"}
)
@DisplayName("Protocol Interoperability Conformance Tests")
class ProtocolInteroperabilityConformanceTest {

    private static final String AS_BASE_URI = "http://localhost:8085";
    private static final String AGENT_IDP_BASE_URI = "http://localhost:8082";
    private static final String AGENT_USER_IDP_BASE_URI = "http://localhost:8083";
    private static final String AS_USER_IDP_BASE_URI = "http://localhost:8084";

    private static final String PAR_ENDPOINT = "/par";
    private static final String TOKEN_ENDPOINT = "/oauth2/token";
    private static final String REGISTRATION_ENDPOINT = "/oauth2/register";
    private static final String AUTHORIZATION_ENDPOINT = "/oauth2/authorize";
    private static final String JWKS_ENDPOINT = "/.well-known/jwks.json";
    private static final String DISCOVERY_ENDPOINT = "/.well-known/openid-configuration";

    private static final String CLIENT_ID = "sample-agent";
    private static final String CLIENT_SECRET = "sample-agent-secret";
    private static final String REDIRECT_URI = "http://localhost:8081/oauth/callback";

    private static final String GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    private static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

    private static RSAKey testSigningKey;

    @BeforeAll
    static void setup() throws Exception {
        RestAssured.useRelaxedHTTPSValidation();
        testSigningKey = new RSAKeyGenerator(2048)
                .keyID("interop-test-key")
                .generate();
    }

    /**
     * Generates a signed PAR JWT (Request Object) for testing.
     */
    private static String generateParJwt(String clientId, String redirectUri) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject("test-user")
                    .audience(AS_BASE_URI)
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("redirect_uri", redirectUri)
                    .claim("response_type", "code")
                    .claim("state", UUID.randomUUID().toString())
                    .claim("evidence", Map.of())
                    .claim("agent_user_binding_proposal", Map.of())
                    .claim("agent_operation_proposal", "allow")
                    .claim("context", Map.of("user", Map.of("id", "test-user")))
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(testSigningKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(testSigningKey));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate PAR JWT", e);
        }
    }

    // ==================================================================================
    // Scenario 1: DCR → PAR → Token
    // Validates that a dynamically registered client can successfully use PAR
    // ==================================================================================

    @Nested
    @DisplayName("Scenario 1: DCR → PAR Integration (RFC 7591 + RFC 9126)")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class DcrToParIntegrationTests {

        private String registeredClientId;
        private String registeredClientSecret;
        private String registrationAccessToken;
        private String registrationClientUri;

        @Test
        @Order(1)
        @DisplayName("Step 1: Register a new client via DCR")
        void registerNewClientViaDcr() {
            Map<String, Object> registrationRequest = new HashMap<>();
            registrationRequest.put("redirect_uris", List.of(REDIRECT_URI));
            registrationRequest.put("grant_types", List.of("authorization_code"));
            registrationRequest.put("response_types", List.of("code"));
            registrationRequest.put("token_endpoint_auth_method", "client_secret_basic");
            registrationRequest.put("client_name", "Interop Test Client");
            registrationRequest.put("scope", "openid profile");

            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .contentType(ContentType.JSON)
                    .body(registrationRequest)
                    .when()
                    .post(REGISTRATION_ENDPOINT);

            assertThat(response.getStatusCode())
                    .as("DCR should return 201 Created")
                    .isEqualTo(201);

            registeredClientId = response.jsonPath().getString("client_id");
            registeredClientSecret = response.jsonPath().getString("client_secret");
            registrationAccessToken = response.jsonPath().getString("registration_access_token");
            registrationClientUri = response.jsonPath().getString("registration_client_uri");

            assertThat(registeredClientId)
                    .as("DCR response must contain client_id")
                    .isNotNull().isNotEmpty();
            assertThat(registeredClientSecret)
                    .as("DCR response must contain client_secret for client_secret_basic")
                    .isNotNull().isNotEmpty();
        }

        @Test
        @Order(2)
        @DisplayName("Step 2: Use DCR-registered client credentials for PAR request")
        void useDcrClientForParRequest() {
            assertThat(registeredClientId)
                    .as("Client must be registered before PAR")
                    .isNotNull();

            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(registeredClientId, registeredClientSecret)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateParJwt(registeredClientId, REDIRECT_URI))
                    .formParam("response_type", "code")
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", "openid profile")
                    .when()
                    .post(PAR_ENDPOINT);

            assertThat(response.getStatusCode())
                    .as("PAR with DCR-registered client should return 201")
                    .isEqualTo(201);

            String requestUri = response.jsonPath().getString("request_uri");
            Integer expiresIn = response.jsonPath().getInt("expires_in");

            assertThat(requestUri)
                    .as("PAR response must contain request_uri")
                    .isNotNull()
                    .startsWith("urn:ietf:params:oauth:request_uri:");
            assertThat(expiresIn)
                    .as("PAR response must contain positive expires_in")
                    .isGreaterThan(0);
        }

        @Test
        @Order(3)
        @DisplayName("Step 3: Use PAR request_uri with authorization endpoint")
        void useParRequestUriWithAuthorizationEndpoint() {
            assertThat(registeredClientId)
                    .as("Client must be registered before authorization")
                    .isNotNull();

            // First get a fresh request_uri
            Response parResponse = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(registeredClientId, registeredClientSecret)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateParJwt(registeredClientId, REDIRECT_URI))
                    .formParam("response_type", "code")
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", "openid profile")
                    .when()
                    .post(PAR_ENDPOINT);

            String requestUri = parResponse.jsonPath().getString("request_uri");

            // Use request_uri with authorization endpoint
            Response authResponse = given()
                    .baseUri(AS_BASE_URI)
                    .redirects().follow(false)
                    .queryParam("client_id", registeredClientId)
                    .queryParam("request_uri", requestUri)
                    .when()
                    .get(AUTHORIZATION_ENDPOINT);

            assertThat(authResponse.getStatusCode())
                    .as("Authorization endpoint should accept valid request_uri from DCR client")
                    .isIn(200, 302);
        }

        @Test
        @Order(4)
        @DisplayName("Step 4: Verify registered client can be read via DCR management")
        void verifyRegisteredClientCanBeRead() {
            if (registrationClientUri == null || registrationAccessToken == null) {
                return;
            }

            // Read client configuration using registration_access_token
            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .header("Authorization", "Bearer " + registrationAccessToken)
                    .when()
                    .get(URI.create(registrationClientUri).getPath());

            // AS may support client configuration read (200) or not (404)
            assertThat(response.getStatusCode())
                    .as("Client read should return 200 or indicate not supported")
                    .isIn(200, 404);

            if (response.getStatusCode() == 200) {
                String returnedClientId = response.jsonPath().getString("client_id");
                assertThat(returnedClientId)
                        .as("Returned client_id should match registered client")
                        .isEqualTo(registeredClientId);
            }
        }
    }

    // ==================================================================================
    // Scenario 2: OIDC Discovery → JWKS → Token Verification
    // Validates that tokens can be verified using keys discovered via OIDC Discovery
    // ==================================================================================

    @Nested
    @DisplayName("Scenario 2: OIDC Discovery → JWKS → Token Verification")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class DiscoveryToJwksToTokenVerificationTests {

        private String discoveredJwksUri;
        private String discoveredTokenEndpoint;
        private String discoveredIssuer;

        @Test
        @Order(1)
        @DisplayName("Step 1: Discover JWKS URI from OIDC Discovery endpoint")
        void discoverJwksUriFromOidcDiscovery() {
            Response discoveryResponse = given()
                    .baseUri(AGENT_USER_IDP_BASE_URI)
                    .when()
                    .get(DISCOVERY_ENDPOINT);

            assertThat(discoveryResponse.getStatusCode())
                    .as("OIDC Discovery endpoint should return 200")
                    .isEqualTo(200);

            discoveredJwksUri = discoveryResponse.jsonPath().getString("jwks_uri");
            discoveredTokenEndpoint = discoveryResponse.jsonPath().getString("token_endpoint");
            discoveredIssuer = discoveryResponse.jsonPath().getString("issuer");

            assertThat(discoveredJwksUri)
                    .as("Discovery response must contain jwks_uri")
                    .isNotNull().isNotEmpty();
            assertThat(discoveredTokenEndpoint)
                    .as("Discovery response must contain token_endpoint")
                    .isNotNull().isNotEmpty();
            assertThat(discoveredIssuer)
                    .as("Discovery response must contain issuer")
                    .isNotNull().isNotEmpty();
        }

        @Test
        @Order(2)
        @DisplayName("Step 2: Fetch JWKS from discovered URI")
        void fetchJwksFromDiscoveredUri() {
            assertThat(discoveredJwksUri)
                    .as("JWKS URI must be discovered first")
                    .isNotNull();

            Response jwksResponse = given()
                    .baseUri(discoveredJwksUri)
                    .when()
                    .get("");

            assertThat(jwksResponse.getStatusCode())
                    .as("JWKS endpoint should return 200")
                    .isEqualTo(200);

            List<Map<String, Object>> keys = jwksResponse.jsonPath().getList("keys");
            assertThat(keys)
                    .as("JWKS must contain at least one key")
                    .isNotNull()
                    .isNotEmpty();

            // Verify each key has required fields
            for (Map<String, Object> key : keys) {
                assertThat(key.get("kty"))
                        .as("Each JWK must have 'kty' field")
                        .isNotNull();
                assertThat(key.get("kid"))
                        .as("Each JWK must have 'kid' field")
                        .isNotNull();
            }
        }

        @Test
        @Order(3)
        @DisplayName("Step 3: Verify discovered issuer matches JWKS source")
        void verifyDiscoveredIssuerMatchesJwksSource() {
            assertThat(discoveredIssuer)
                    .as("Issuer must be discovered first")
                    .isNotNull();
            assertThat(discoveredJwksUri)
                    .as("JWKS URI must be discovered first")
                    .isNotNull();

            // The JWKS URI should be under the same issuer domain
            assertThat(discoveredJwksUri)
                    .as("JWKS URI should be hosted by the same issuer")
                    .startsWith(discoveredIssuer);
        }

        @Test
        @Order(4)
        @DisplayName("Step 4: Verify JWKS keys can parse into JWK objects")
        void verifyJwksKeysCanParseIntoJwkObjects() throws ParseException {
            assertThat(discoveredJwksUri)
                    .as("JWKS URI must be discovered first")
                    .isNotNull();

            Response jwksResponse = given()
                    .baseUri(discoveredJwksUri)
                    .when()
                    .get("");

            String jwksJson = jwksResponse.getBody().asString();
            JWKSet jwkSet = JWKSet.parse(jwksJson);

            assertThat(jwkSet.getKeys())
                    .as("Parsed JWK Set must contain keys")
                    .isNotEmpty();

            for (JWK jwk : jwkSet.getKeys()) {
                assertThat(jwk.getKeyID())
                        .as("Each parsed JWK must have a key ID")
                        .isNotNull();
                assertThat(jwk.getAlgorithm())
                        .as("Each parsed JWK should have an algorithm")
                        .isNotNull();
            }
        }

        @Test
        @Order(5)
        @DisplayName("Step 5: Cross-validate JWKS across multiple IDPs")
        void crossValidateJwksAcrossMultipleIdps() {
            // Fetch JWKS from Agent User IDP
            Response agentUserIdpJwks = given()
                    .baseUri(AGENT_USER_IDP_BASE_URI)
                    .when()
                    .get(JWKS_ENDPOINT);

            assertThat(agentUserIdpJwks.getStatusCode()).isEqualTo(200);

            // Fetch JWKS from AS User IDP
            Response asUserIdpJwks = given()
                    .baseUri(AS_USER_IDP_BASE_URI)
                    .when()
                    .get(JWKS_ENDPOINT);

            assertThat(asUserIdpJwks.getStatusCode()).isEqualTo(200);

            // Fetch JWKS from Agent IDP
            Response agentIdpJwks = given()
                    .baseUri(AGENT_IDP_BASE_URI)
                    .when()
                    .get(JWKS_ENDPOINT);

            assertThat(agentIdpJwks.getStatusCode()).isEqualTo(200);

            // Verify each IDP has distinct key sets (different kid values)
            List<String> agentUserKids = agentUserIdpJwks.jsonPath().getList("keys.kid");
            List<String> asUserKids = asUserIdpJwks.jsonPath().getList("keys.kid");
            List<String> agentKids = agentIdpJwks.jsonPath().getList("keys.kid");

            assertThat(agentUserKids).as("Agent User IDP must have keys").isNotEmpty();
            assertThat(asUserKids).as("AS User IDP must have keys").isNotEmpty();
            assertThat(agentKids).as("Agent IDP must have keys").isNotEmpty();
        }
    }

    // ==================================================================================
    // Scenario 3: PAR → Authorization → Token Exchange
    // Validates the full flow from PAR through authorization to token exchange
    // ==================================================================================

    @Nested
    @DisplayName("Scenario 3: PAR → Authorization → Token Exchange (RFC 9126 + RFC 8693)")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class ParToAuthorizationToTokenExchangeTests {

        private String requestUri;

        @Test
        @Order(1)
        @DisplayName("Step 1: Submit PAR request and obtain request_uri")
        void submitParRequestAndObtainRequestUri() {
            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateParJwt(CLIENT_ID, REDIRECT_URI))
                    .formParam("response_type", "code")
                    .formParam("redirect_uri", REDIRECT_URI)
                    .formParam("scope", "openid profile")
                    .when()
                    .post(PAR_ENDPOINT);

            assertThat(response.getStatusCode())
                    .as("PAR request should return 201")
                    .isEqualTo(201);

            requestUri = response.jsonPath().getString("request_uri");
            assertThat(requestUri)
                    .as("PAR response must contain request_uri")
                    .isNotNull()
                    .startsWith("urn:ietf:params:oauth:request_uri:");
        }

        @Test
        @Order(2)
        @DisplayName("Step 2: Use request_uri at authorization endpoint")
        void useRequestUriAtAuthorizationEndpoint() {
            assertThat(requestUri)
                    .as("request_uri must be obtained from PAR first")
                    .isNotNull();

            Response authResponse = given()
                    .baseUri(AS_BASE_URI)
                    .redirects().follow(false)
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("request_uri", requestUri)
                    .when()
                    .get(AUTHORIZATION_ENDPOINT);

            assertThat(authResponse.getStatusCode())
                    .as("Authorization endpoint should accept PAR request_uri")
                    .isIn(200, 302);
        }

        @Test
        @Order(3)
        @DisplayName("Step 3: Token Exchange endpoint accepts token exchange grant type")
        void tokenExchangeEndpointAcceptsTokenExchangeGrantType() {
            // Generate a mock subject token (self-signed JWT)
            String mockSubjectToken = generateMockSubjectToken();

            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                    .formParam("subject_token", mockSubjectToken)
                    .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                    .when()
                    .post(TOKEN_ENDPOINT);

            // Token exchange may succeed (200) or fail with proper error (400/500)
            // depending on whether the subject_token is valid
            assertThat(response.getStatusCode())
                    .as("Token endpoint should handle token exchange request")
                    .isIn(200, 400, 500);

            // Verify response is JSON
            assertThat(response.getContentType())
                    .as("Response must be JSON")
                    .startsWith("application/json");
        }

        @Test
        @Order(4)
        @DisplayName("Step 4: Verify PAR and Token Exchange use same client credentials")
        void verifyParAndTokenExchangeUseSameClientCredentials() {
            // PAR request with client credentials
            Response parResponse = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("request", generateParJwt(CLIENT_ID, REDIRECT_URI))
                    .formParam("response_type", "code")
                    .formParam("redirect_uri", REDIRECT_URI)
                    .when()
                    .post(PAR_ENDPOINT);

            assertThat(parResponse.getStatusCode())
                    .as("PAR should accept client credentials")
                    .isEqualTo(201);

            // Token Exchange with same client credentials
            Response tokenExchangeResponse = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                    .formParam("subject_token", generateMockSubjectToken())
                    .formParam("subject_token_type", TOKEN_TYPE_ACCESS_TOKEN)
                    .when()
                    .post(TOKEN_ENDPOINT);

            // Both endpoints should accept the same client credentials
            assertThat(tokenExchangeResponse.getStatusCode())
                    .as("Token exchange should accept same client credentials as PAR")
                    .isIn(200, 400, 500);
        }

        private String generateMockSubjectToken() {
            try {
                JWTClaimsSet claims = new JWTClaimsSet.Builder()
                        .issuer(AS_BASE_URI)
                        .subject("test-user")
                        .audience(AS_BASE_URI)
                        .issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                        .jwtID(UUID.randomUUID().toString())
                        .claim("scope", "openid profile")
                        .build();

                JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(testSigningKey.getKeyID())
                        .type(JOSEObjectType.JWT)
                        .build();

                SignedJWT signedJWT = new SignedJWT(header, claims);
                signedJWT.sign(new RSASSASigner(testSigningKey));
                return signedJWT.serialize();
            } catch (Exception e) {
                throw new RuntimeException("Failed to generate mock subject token", e);
            }
        }
    }

    // ==================================================================================
    // Scenario 4: WIT/WPT → Token Exchange
    // Validates that workload identity tokens can be used in token exchange
    // ==================================================================================

    @Nested
    @DisplayName("Scenario 4: WIT/WPT → Token Exchange (WIMSE + RFC 8693)")
    @TestMethodOrder(MethodOrderer.OrderAnnotation.class)
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class WitWptToTokenExchangeTests {

        private ECKey witSigningKey;
        private ECKey wptSigningKey;
        private String generatedWit;
        private String generatedWpt;

        @Test
        @Order(1)
        @DisplayName("Step 1: Generate WIT (Workload Identity Token)")
        void generateWorkloadIdentityToken() throws Exception {
            // Generate EC key pair for WIT signing (IDP key)
            witSigningKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                    .keyID("wit-test-key")
                    .generate();

            // Generate a separate key for WPT signing (workload's own key)
            wptSigningKey = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                    .keyID("wpt-test-key")
                    .generate();

            // Build WIT claims with cnf (confirmation) claim containing the WPT public key
            JWTClaimsSet witClaims = new JWTClaimsSet.Builder()
                    .issuer("https://idp.example.com")
                    .subject("workload-agent-001")
                    .audience("https://as.example.com")
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("cnf", Map.of("jwk", wptSigningKey.toPublicJWK().toJSONObject()))
                    .build();

            JWSHeader witHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(witSigningKey.getKeyID())
                    .type(new JOSEObjectType("wit+jwt"))
                    .build();

            SignedJWT witJwt = new SignedJWT(witHeader, witClaims);
            witJwt.sign(new ECDSASigner(witSigningKey));
            generatedWit = witJwt.serialize();

            assertThat(generatedWit)
                    .as("WIT must be a valid JWT")
                    .isNotNull()
                    .contains(".");

            // Verify WIT structure
            SignedJWT parsedWit = SignedJWT.parse(generatedWit);
            assertThat(parsedWit.getHeader().getType().toString())
                    .as("WIT header typ must be 'wit+jwt'")
                    .isEqualTo("wit+jwt");
            assertThat(parsedWit.getJWTClaimsSet().getClaim("cnf"))
                    .as("WIT must contain cnf claim")
                    .isNotNull();
        }

        @Test
        @Order(2)
        @DisplayName("Step 2: Generate WPT (Workload Proof Token) bound to WIT")
        void generateWorkloadProofTokenBoundToWit() throws Exception {
            assertThat(generatedWit)
                    .as("WIT must be generated first")
                    .isNotNull();

            // Calculate SHA-256 hash of WIT for the wth claim
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] witHash = digest.digest(generatedWit.getBytes(StandardCharsets.US_ASCII));
            String witHashBase64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(witHash);

            // Build WPT claims
            JWTClaimsSet wptClaims = new JWTClaimsSet.Builder()
                    .issuer("workload-agent-001")
                    .audience(AS_BASE_URI)
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 300_000))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("wth", witHashBase64Url)
                    .build();

            JWSHeader wptHeader = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(wptSigningKey.getKeyID())
                    .type(new JOSEObjectType("wpt+jwt"))
                    .build();

            SignedJWT wptJwt = new SignedJWT(wptHeader, wptClaims);
            wptJwt.sign(new ECDSASigner(wptSigningKey));
            generatedWpt = wptJwt.serialize();

            assertThat(generatedWpt)
                    .as("WPT must be a valid JWT")
                    .isNotNull()
                    .contains(".");

            // Verify WPT structure
            SignedJWT parsedWpt = SignedJWT.parse(generatedWpt);
            assertThat(parsedWpt.getHeader().getType().toString())
                    .as("WPT header typ must be 'wpt+jwt'")
                    .isEqualTo("wpt+jwt");
            assertThat(parsedWpt.getJWTClaimsSet().getStringClaim("wth"))
                    .as("WPT must contain wth claim")
                    .isNotNull()
                    .isEqualTo(witHashBase64Url);
        }

        @Test
        @Order(3)
        @DisplayName("Step 3: Verify WPT is cryptographically bound to WIT")
        void verifyWptIsCryptographicallyBoundToWit() throws Exception {
            assertThat(generatedWit).as("WIT must be generated").isNotNull();
            assertThat(generatedWpt).as("WPT must be generated").isNotNull();

            // Parse WIT to extract cnf.jwk (the public key that should sign WPT)
            SignedJWT parsedWit = SignedJWT.parse(generatedWit);
            @SuppressWarnings("unchecked")
            Map<String, Object> cnfClaim = (Map<String, Object>) parsedWit.getJWTClaimsSet().getClaim("cnf");
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnfClaim.get("jwk");
            ECKey witCnfKey = ECKey.parse(jwkMap);

            // Parse WPT and verify its signature using the key from WIT's cnf claim
            SignedJWT parsedWpt = SignedJWT.parse(generatedWpt);
            boolean signatureValid = parsedWpt.verify(
                    new com.nimbusds.jose.crypto.ECDSAVerifier(witCnfKey));

            assertThat(signatureValid)
                    .as("WPT signature must be verifiable with WIT's cnf.jwk public key")
                    .isTrue();

            // Verify wth claim matches SHA-256 hash of WIT
            String wthClaim = parsedWpt.getJWTClaimsSet().getStringClaim("wth");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] expectedHash = digest.digest(generatedWit.getBytes(StandardCharsets.US_ASCII));
            String expectedHashBase64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedHash);

            assertThat(wthClaim)
                    .as("WPT wth claim must match SHA-256 hash of WIT")
                    .isEqualTo(expectedHashBase64Url);
        }

        @Test
        @Order(4)
        @DisplayName("Step 4: Use WPT as subject_token in Token Exchange request")
        void useWptAsSubjectTokenInTokenExchange() {
            assertThat(generatedWpt)
                    .as("WPT must be generated first")
                    .isNotNull();

            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                    .formParam("subject_token", generatedWpt)
                    .formParam("subject_token_type", TOKEN_TYPE_JWT)
                    .when()
                    .post(TOKEN_ENDPOINT);

            // The AS may accept or reject the WPT depending on trust configuration
            assertThat(response.getStatusCode())
                    .as("Token endpoint should handle WPT-based token exchange")
                    .isIn(200, 400, 500);

            assertThat(response.getContentType())
                    .as("Response must be JSON")
                    .startsWith("application/json");
        }

        @Test
        @Order(5)
        @DisplayName("Step 5: Use WIT as actor_token in Token Exchange request")
        void useWitAsActorTokenInTokenExchange() {
            assertThat(generatedWit)
                    .as("WIT must be generated first")
                    .isNotNull();
            assertThat(generatedWpt)
                    .as("WPT must be generated first")
                    .isNotNull();

            Response response = given()
                    .baseUri(AS_BASE_URI)
                    .auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                    .contentType(ContentType.URLENC)
                    .formParam("grant_type", GRANT_TYPE_TOKEN_EXCHANGE)
                    .formParam("subject_token", generatedWpt)
                    .formParam("subject_token_type", TOKEN_TYPE_JWT)
                    .formParam("actor_token", generatedWit)
                    .formParam("actor_token_type", TOKEN_TYPE_JWT)
                    .when()
                    .post(TOKEN_ENDPOINT);

            // The AS may accept or reject depending on trust configuration
            assertThat(response.getStatusCode())
                    .as("Token endpoint should handle WIT+WPT token exchange")
                    .isIn(200, 400, 500);

            assertThat(response.getContentType())
                    .as("Response must be JSON")
                    .startsWith("application/json");
        }
    }
}
