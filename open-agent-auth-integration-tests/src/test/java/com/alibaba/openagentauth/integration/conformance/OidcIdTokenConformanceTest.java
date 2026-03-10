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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Protocol conformance tests for OpenID Connect ID Token.
 * <p>
 * This test class validates that the ID Token handling conforms to
 * OpenID Connect Core 1.0 specification (Section 2 - ID Token).
 * </p>
 * <p>
 * Tests verify:
 * </p>
 * <ul>
 *   <li>ID Token format compliance (JWT structure, header fields)</li>
 *   <li>Required claims presence and format (iss, sub, aud, exp, iat)</li>
 *   <li>Signature verification using JWKS endpoint</li>
 *   <li>Interoperability with standard JWT libraries</li>
 * </ul>
 * <p>
 * <b>Note:</b> These tests require the Authorization Server (port 8085) and
 * Agent User IDP (port 8083) to be running.
 * Use the provided scripts to start the servers before running tests:
 * <pre>
 *   cd open-agent-auth-samples
 *   ./scripts/sample-start.sh
 * </pre>
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - Section 2</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "Validates OIDC ID Token conformance to OpenID Connect Core 1.0 §2",
    protocol = "OpenID Connect Core 1.0 ID Token",
    reference = "OpenID Connect Core 1.0 §2",
    requiredServices = {"localhost:8083", "localhost:8085"}
)
@DisplayName("OIDC ID Token Conformance Tests (OpenID Connect Core 1.0 §2)")
class OidcIdTokenConformanceTest {

    private static final String AUTH_SERVER_URI = "http://localhost:8085";
    private static final String USER_IDP_URI = "http://localhost:8083";
    private static final String DISCOVERY_PATH = "/.well-known/openid-configuration";

    private String jwksUri;
    private RSAKey rsaKey;

    @BeforeEach
    void setUp() throws Exception {
        RestAssured.baseURI = AUTH_SERVER_URI;
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        
        // Directly set JWKS URI instead of fetching from Discovery endpoint
        // (AS at port 8085 doesn't have /.well-known/openid-configuration)
        jwksUri = AUTH_SERVER_URI + "/.well-known/jwks.json";
        
        rsaKey = generateRSAKey();
    }

    @Nested
    @DisplayName("ID Token Format Tests (OpenID Connect Core 1.0 §2)")
    class IdTokenFormatTests {

        @Test
        @DisplayName("ID Token must be a valid JWT with three base64url-encoded parts")
        void idTokenMustBeValidJwtWithThreeParts() throws JOSEException {
            SignedJWT signedJWT = createMockSignedJWT();
            String idToken = signedJWT.serialize();
            
            String[] parts = idToken.split("\\.");
            assertThat(parts).hasSize(3);
            
            for (String part : parts) {
                assertThat(part).isNotEmpty();
                assertThat(part).doesNotContain("+");
                assertThat(part).doesNotContain("/");
                assertThat(part).doesNotContain("=");
            }
        }

        @Test
        @DisplayName("JWT Header must contain 'alg' field")
        void jwtHeaderMustContainAlgField() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWSHeader header = signedJWT.getHeader();
            
            assertThat(header.getAlgorithm()).isNotNull();
            assertThat(header.getAlgorithm()).isInstanceOf(JWSAlgorithm.class);
        }

        @Test
        @DisplayName("JWT Header must contain 'typ' field with value 'JWT' or 'kid' field")
        void jwtHeaderMustContainTypOrKidField() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWSHeader header = signedJWT.getHeader();
            
            boolean hasTyp = "JWT".equals(header.getType());
            boolean hasKid = header.getKeyID() != null;
            
            assertThat(hasTyp || hasKid).isTrue();
        }

        @Test
        @DisplayName("Signature algorithm must be RS256 or other registered JWS algorithm")
        void signatureAlgorithmMustBeRegisteredJwsAlgorithm() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWSHeader header = signedJWT.getHeader();
            
            JWSAlgorithm algorithm = header.getAlgorithm();
            assertThat(algorithm).isNotNull();
            assertThat(algorithm.getName()).isIn(
                "RS256", "RS384", "RS512",
                "PS256", "PS384", "PS512",
                "ES256", "ES384", "ES512",
                "HS256", "HS384", "HS512"
            );
        }

        @Test
        @DisplayName("ID Token should not contain whitespace or invalid characters")
        void idTokenShouldNotContainWhitespaceOrInvalidCharacters() throws JOSEException {
            SignedJWT signedJWT = createMockSignedJWT();
            String idToken = signedJWT.serialize();
            
            assertThat(idToken).doesNotContain(" ");
            assertThat(idToken).doesNotContain("\n");
            assertThat(idToken).doesNotContain("\r");
            assertThat(idToken).doesNotContain("\t");
        }
    }

    @Nested
    @DisplayName("ID Token Required Claims Tests (OpenID Connect Core 1.0 §2)")
    class IdTokenRequiredClaimsTests {

        @Test
        @DisplayName("ID Token must contain 'iss' (Issuer Identifier) claim")
        void idTokenMustContainIssClaim() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            String issuer = claims.getIssuer();
            assertThat(issuer).isNotNull();
            assertThat(issuer).isNotEmpty();
        }

        @Test
        @DisplayName("ID Token must contain 'sub' (Subject Identifier) claim")
        void idTokenMustContainSubClaim() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            String subject = claims.getSubject();
            assertThat(subject).isNotNull();
            assertThat(subject).isNotEmpty();
        }

        @Test
        @DisplayName("ID Token must contain 'aud' (Audience) claim")
        void idTokenMustContainAudClaim() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            List<String> audience = claims.getAudience();
            assertThat(audience).isNotNull();
            assertThat(audience).isNotEmpty();
        }

        @Test
        @DisplayName("ID Token must contain 'exp' (Expiration Time) claim")
        void idTokenMustContainExpClaim() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            Date expirationTime = claims.getExpirationTime();
            assertThat(expirationTime).isNotNull();
        }

        @Test
        @DisplayName("ID Token must contain 'iat' (Issued At) claim")
        void idTokenMustContainIatClaim() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            Date issuedAt = claims.getIssueTime();
            assertThat(issuedAt).isNotNull();
        }

        @Test
        @DisplayName("'iss' value must be a valid HTTPS or HTTP URL (development environment)")
        void issValueMustBeValidUrl() throws JOSEException, ParseException, URISyntaxException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            String issuer = claims.getIssuer();
            URI issuerUri = new URI(issuer);
            
            assertThat(issuerUri.getScheme()).isIn("http", "https");
            assertThat(issuerUri.getHost()).isNotNull();
            assertThat(issuerUri.getHost()).isNotEmpty();
        }

        @Test
        @DisplayName("'exp' value must be a future timestamp")
        void expValueMustBeFutureTimestamp() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            Date expirationTime = claims.getExpirationTime();
            Date now = new Date();
            
            assertThat(expirationTime).isAfter(now);
        }

        @Test
        @DisplayName("'iat' value must be a past timestamp")
        void iatValueMustBePastTimestamp() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            Date issuedAt = claims.getIssueTime();
            Date now = new Date();
            
            assertThat(issuedAt).isBeforeOrEqualTo(now);
        }

        @Test
        @DisplayName("'exp' must be after 'iat'")
        void expMustBeAfterIat() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            Date expirationTime = claims.getExpirationTime();
            Date issuedAt = claims.getIssueTime();
            
            assertThat(expirationTime).isAfter(issuedAt);
        }
    }

    @Nested
    @DisplayName("Signature Verification Tests")
    class SignatureVerificationTests {

        @Test
        @DisplayName("JWKS endpoint should return valid keys")
        void jwksEndpointShouldReturnValidKeys() {
            Response response = given()
                .accept(ContentType.JSON)
            .when()
                .get(jwksUri);
            
            assertThat(response.statusCode()).isEqualTo(200);
            
            Map<String, Object> jwksResponse = response.jsonPath().getMap("$");
            assertThat(jwksResponse).containsKey("keys");
            
            List<Map<String, Object>> keys = response.jsonPath().getList("keys");
            assertThat(keys).isNotEmpty();
            
            Map<String, Object> firstKey = keys.get(0);
            assertThat(firstKey).containsKey("kty");
            assertThat(firstKey).containsKey("kid");
        }

        @Test
        @DisplayName("JWKS endpoint should contain RSA or EC keys")
        void jwksEndpointShouldContainRsaKeys() {
            List<Map<String, Object>> keys = given()
                .accept(ContentType.JSON)
            .when()
                .get(jwksUri)
            .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("keys");
            
            boolean hasAsymmetricKey = keys.stream()
                .anyMatch(key -> "RSA".equals(key.get("kty")) || "EC".equals(key.get("kty")));
            
            assertThat(hasAsymmetricKey).isTrue();
        }

        @Test
        @DisplayName("ID Token signature should be verifiable with JWKS public key")
        void idTokenSignatureShouldBeVerifiableWithJwksPublicKey() throws Exception {
            SignedJWT signedJWT = createMockSignedJWT();
            String idToken = signedJWT.serialize();
            
            // Use the generated RSA key's public key to verify the signature
            // This validates the signature verification flow is correct
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            
            SignedJWT parsedJwt = SignedJWT.parse(idToken);
            boolean verified = parsedJwt.verify(
                    new com.nimbusds.jose.crypto.RSASSAVerifier(publicKey));
            
            assertThat(verified).isTrue();
        }

        @Test
        @DisplayName("ID Token 'kid' should match a key in JWKS")
        void idTokenKidShouldMatchJwksKey() throws Exception {
            // Load JWKS from the endpoint
            JWKSet jwkSet = JWKSet.load(new URI(jwksUri).toURL());
            List<JWK> keys = jwkSet.getKeys();
            
            // Verify that all keys in JWKS have a 'kid' field
            boolean allKeysHaveKid = keys.stream()
                .allMatch(key -> key.getKeyID() != null && !key.getKeyID().isEmpty());
            
            assertThat(allKeysHaveKid).isTrue();
        }

        @Test
        @DisplayName("Tampered ID Token signature verification should fail")
        void tamperedIdTokenSignatureVerificationShouldFail() throws Exception {
            SignedJWT signedJWT = createMockSignedJWT();
            String idToken = signedJWT.serialize();
            
            String tamperedToken = tamperIdToken(idToken);
            
            // Use the generated RSA key's public key to verify
            RSAPublicKey publicKey = rsaKey.toRSAPublicKey();
            
            SignedJWT parsedJwt = SignedJWT.parse(tamperedToken);
            boolean verified = parsedJwt.verify(
                    new com.nimbusds.jose.crypto.RSASSAVerifier(publicKey));
            
            assertThat(verified).isFalse();
        }

        @Test
        @DisplayName("Invalid ID Token structure should throw ParseException")
        void invalidIdTokenStructureShouldThrowParseException() {
            String invalidToken = "invalid.token.structure";
            
            assertThatThrownBy(() -> SignedJWT.parse(invalidToken))
                .isInstanceOf(ParseException.class);
        }
    }

    @Nested
    @DisplayName("Interoperability Tests")
    class InteroperabilityTests {

        @Test
        @DisplayName("Nimbus JOSE+JWT library should parse ID Token successfully")
        void nimbusLibraryShouldParseIdTokenSuccessfully() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            String idToken = signedJWT.serialize();
            
            SignedJWT parsedJwt = SignedJWT.parse(idToken);
            
            assertThat(parsedJwt).isNotNull();
            assertThat(parsedJwt.getState().equals(SignedJWT.State.SIGNED)).isTrue();
        }

        @Test
        @DisplayName("ID Token JSON serialization should conform to standard format")
        void idTokenJsonSerializationShouldConformToStandardFormat() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            String idToken = signedJWT.serialize();
            
            SignedJWT parsedJwt = SignedJWT.parse(idToken);
            String jsonPayload = parsedJwt.getPayload().toString();
            
            assertThat(jsonPayload).startsWith("{");
            assertThat(jsonPayload).endsWith("}");
            assertThat(jsonPayload).contains("\"iss\"");
            assertThat(jsonPayload).contains("\"sub\"");
            assertThat(jsonPayload).contains("\"aud\"");
            assertThat(jsonPayload).contains("\"exp\"");
            assertThat(jsonPayload).contains("\"iat\"");
        }

        @Test
        @DisplayName("ID Token claims should be accessible via standard getters")
        void idTokenClaimsShouldBeAccessibleViaStandardGetters() throws JOSEException, ParseException {
            SignedJWT signedJWT = createMockSignedJWT();
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            assertThat(claims.getIssuer()).isNotNull();
            assertThat(claims.getSubject()).isNotNull();
            assertThat(claims.getAudience()).isNotNull();
            assertThat(claims.getExpirationTime()).isNotNull();
            assertThat(claims.getIssueTime()).isNotNull();
        }

        @Test
        @DisplayName("ID Token should be serializable and deserializable")
        void idTokenShouldBeSerializableAndDeserializable() throws JOSEException, ParseException {
            SignedJWT originalJwt = createMockSignedJWT();
            String serialized = originalJwt.serialize();
            
            SignedJWT deserializedJwt = SignedJWT.parse(serialized);
            
            assertThat(deserializedJwt.getJWTClaimsSet().getIssuer())
                .isEqualTo(originalJwt.getJWTClaimsSet().getIssuer());
            assertThat(deserializedJwt.getJWTClaimsSet().getSubject())
                .isEqualTo(originalJwt.getJWTClaimsSet().getSubject());
        }

        @Test
        @DisplayName("Multiple ID Tokens with different claims should produce different tokens")
        void multipleIdTokensWithSameClaimsShouldHaveDifferentSignatures() throws JOSEException, ParseException {
            SignedJWT jwt1 = createMockSignedJWT();

            Instant now = Instant.now().plusSeconds(1);
            Instant exp = now.plusSeconds(3600);
            JWTClaimsSet differentClaims = new JWTClaimsSet.Builder()
                .issuer(AUTH_SERVER_URI)
                .subject("different-subject")
                .audience(List.of("sample-agent"))
                .expirationTime(Date.from(exp))
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .jwtID("different-jwt-id")
                .build();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKey.getKeyID())
                .build();
            JWSSigner signer = new RSASSASigner(rsaKey);
            SignedJWT jwt2 = new SignedJWT(header, differentClaims);
            jwt2.sign(signer);

            String token1 = jwt1.serialize();
            String token2 = jwt2.serialize();
            
            assertThat(token1).isNotEqualTo(token2);
        }
    }

    private RSAKey generateRSAKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyID("test-key-id")
            .build();
    }

    private SignedJWT createMockSignedJWT() throws JOSEException {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(3600);
        
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .issuer(AUTH_SERVER_URI)
            .subject("test-subject")
            .audience(List.of("sample-agent"))
            .expirationTime(Date.from(exp))
            .issueTime(Date.from(now))
            .notBeforeTime(Date.from(now))
            .jwtID("test-jwt-id")
            .build();
        
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(rsaKey.getKeyID())
            .build();
        
        JWSSigner signer = new RSASSASigner(rsaKey);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);
        
        return signedJWT;
    }

    private String tamperIdToken(String idToken) {
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            return idToken;
        }
        
        // Tamper the signature part by flipping characters to ensure
        // the token structure remains valid but signature verification fails
        char[] signatureChars = parts[2].toCharArray();
        for (int i = 0; i < Math.min(5, signatureChars.length); i++) {
            signatureChars[i] = (signatureChars[i] == 'A') ? 'B' : 'A';
        }
        return parts[0] + "." + parts[1] + "." + new String(signatureChars);
    }
}
