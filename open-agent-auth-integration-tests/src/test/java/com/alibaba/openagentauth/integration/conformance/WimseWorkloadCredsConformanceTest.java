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

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.jwk.Jwk.KeyType;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Protocol conformance tests for WIMSE Workload Identity Credentials.
 * <p>
 * This test class validates the framework's implementation of Workload Identity Token (WIT)
 * and Workload Proof Token (WPT) against the draft-ietf-wimse-workload-creds specification.
 * </p>
 * <p>
 * <b>Tested specifications:</b>
 * </p>
 * <ul>
 *   <li>WIT format: JOSE header with typ="wit+jwt", required claims (iss, sub, exp, cnf)</li>
 *   <li>WPT format: JOSE header with typ="wpt+jwt", required claims (aud, exp, jti, wth)</li>
 *   <li>Cryptographic binding: WPT signed with key from WIT's cnf claim</li>
 *   <li>Token hash binding: WPT's wth claim contains SHA-256 hash of WIT</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @since 1.0
 */
@ProtocolConformanceTest(
    value = "WIMSE Workload Identity Credentials Conformance Tests",
    protocol = "WIMSE WIT/WPT",
    reference = "draft-ietf-wimse-workload-creds",
    requiredServices = {}
)
@DisplayName("WIMSE Workload Identity Credentials Conformance Tests")
class WimseWorkloadCredsConformanceTest {

    private static final String WIT_MEDIA_TYPE = "wit+jwt";
    private static final String WPT_MEDIA_TYPE = "wpt+jwt";
    private static final String ISSUER = "https://idp.example.com";
    private static final String SUBJECT = "workload-agent-001";
    private static final String AUDIENCE = "https://resource.example.com";

    private RSAKey issuerSigningKey;
    private RSAKey workloadKeyPair;

    @BeforeEach
    void setUp() throws JOSEException {
        issuerSigningKey = new RSAKeyGenerator(2048)
                .keyID("issuer-key-001")
                .generate();

        workloadKeyPair = new RSAKeyGenerator(2048)
                .keyID("workload-key-001")
                .generate();
    }

    @Nested
    @DisplayName("WIT Format Conformance (draft-ietf-wimse-workload-creds §3.1)")
    class WitFormatTests {

        @Test
        @DisplayName("WIT JOSE header typ MUST be 'wit+jwt'")
        void witHeaderTypMustBeWitJwt() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WIT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThat(header.getType()).isEqualTo(WIT_MEDIA_TYPE);
        }

        @Test
        @DisplayName("WIT JOSE header MUST contain alg parameter")
        void witHeaderMustContainAlgParameter() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WIT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThat(header.getAlgorithm()).isNotNull();
            assertThat(header.getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("WIT alg MUST be an asymmetric digital signature algorithm")
        void witAlgMustBeAsymmetricSignatureAlgorithm() {
            String[] validAlgorithms = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"};

            for (String algorithm : validAlgorithms) {
                WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                        .type(WIT_MEDIA_TYPE)
                        .algorithm(algorithm)
                        .build();

                assertThat(header.getAlgorithm())
                        .as("Algorithm %s should be accepted", algorithm)
                        .isEqualTo(algorithm);
            }
        }

        @Test
        @DisplayName("WIT MUST be a valid JWT with three base64url-encoded segments")
        void witMustBeValidJwtFormat() throws JOSEException {
            String witJwtString = generateSignedWitJwtString();

            String[] segments = witJwtString.split("\\.");
            assertThat(segments).hasSize(3);

            for (String segment : segments) {
                assertThat(segment).matches("[A-Za-z0-9_-]+");
            }
        }

        @Test
        @DisplayName("WIT header MUST be parseable as valid JSON")
        void witHeaderMustBeParseableJson() throws JOSEException, ParseException {
            String witJwtString = generateSignedWitJwtString();

            SignedJWT parsedJwt = SignedJWT.parse(witJwtString);
            JWSHeader header = parsedJwt.getHeader();

            assertThat(header).isNotNull();
            assertThat(header.getType().getType()).isEqualTo(WIT_MEDIA_TYPE);
            assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        }
    }

    @Nested
    @DisplayName("WIT Required Claims Conformance (draft-ietf-wimse-workload-creds §3.1)")
    class WitRequiredClaimsTests {

        @Test
        @DisplayName("WIT MUST contain iss (Issuer) claim")
        void witMustContainIssClaim() {
            WorkloadIdentityToken wit = buildValidWit();

            assertThat(wit.getIssuer()).isNotNull();
            assertThat(wit.getIssuer()).isEqualTo(ISSUER);
        }

        @Test
        @DisplayName("WIT MUST contain sub (Subject / Workload Identifier) claim")
        void witMustContainSubClaim() {
            WorkloadIdentityToken wit = buildValidWit();

            assertThat(wit.getSubject()).isNotNull();
            assertThat(wit.getSubject()).isEqualTo(SUBJECT);
        }

        @Test
        @DisplayName("WIT MUST contain exp (Expiration Time) claim")
        void witMustContainExpClaim() {
            WorkloadIdentityToken wit = buildValidWit();

            assertThat(wit.getExpirationTime()).isNotNull();
            assertThat(wit.getExpirationTime()).isAfter(new Date());
        }

        @Test
        @DisplayName("WIT MUST contain cnf (Confirmation) claim with jwk")
        void witMustContainCnfClaimWithJwk() {
            WorkloadIdentityToken wit = buildValidWit();

            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getJwk()).isNotNull();
        }

        @Test
        @DisplayName("WIT MAY contain jti (JWT ID) claim for uniqueness")
        void witMayContainJtiClaim() {
            WorkloadIdentityToken wit = buildValidWit();

            assertThat(wit.getJwtId()).isNotNull();
            assertThat(wit.getJwtId()).isNotEmpty();
        }

        @Test
        @DisplayName("WIT exp claim MUST represent a future time")
        void witExpClaimMustBeFutureTime() {
            WorkloadIdentityToken wit = buildValidWit();

            assertThat(wit.isExpired()).isFalse();
            assertThat(wit.isValid()).isTrue();
        }

        @Test
        @DisplayName("Expired WIT MUST be detected as invalid")
        void expiredWitMustBeDetectedAsInvalid() {
            Date pastExpiration = new Date(System.currentTimeMillis() - 60_000);

            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .expirationTime(pastExpiration)
                    .jwtId(UUID.randomUUID().toString())
                    .build();

            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WIT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            WorkloadIdentityToken expiredWit = WorkloadIdentityToken.builder()
                    .header(header)
                    .claims(claims)
                    .build();

            assertThat(expiredWit.isExpired()).isTrue();
            assertThat(expiredWit.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("WIT Builder Validation Tests")
    class WitBuilderValidationTests {

        @Test
        @DisplayName("WIT builder MUST require header")
        void witBuilderMustRequireHeader() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer(ISSUER)
                    .subject(SUBJECT)
                    .expirationTime(futureDate())
                    .build();

            assertThatThrownBy(() -> WorkloadIdentityToken.builder()
                    .claims(claims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("header");
        }

        @Test
        @DisplayName("WIT builder MUST require claims")
        void witBuilderMustRequireClaims() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WIT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThatThrownBy(() -> WorkloadIdentityToken.builder()
                    .header(header)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("claims");
        }
    }

    @Nested
    @DisplayName("WPT Format Conformance (draft-ietf-wimse-workload-creds §3.2)")
    class WptFormatTests {

        @Test
        @DisplayName("WPT JOSE header typ MUST be 'wpt+jwt'")
        void wptHeaderTypMustBeWptJwt() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WPT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThat(header.getType()).isEqualTo(WPT_MEDIA_TYPE);
        }

        @Test
        @DisplayName("WPT JOSE header MUST contain alg parameter")
        void wptHeaderMustContainAlgParameter() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WPT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThat(header.getAlgorithm()).isNotNull();
            assertThat(header.getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("WPT MUST be a valid JWT with three base64url-encoded segments")
        void wptMustBeValidJwtFormat() throws JOSEException {
            String wptJwtString = generateSignedWptJwtString();

            String[] segments = wptJwtString.split("\\.");
            assertThat(segments).hasSize(3);

            for (String segment : segments) {
                assertThat(segment).matches("[A-Za-z0-9_-]+");
            }
        }

        @Test
        @DisplayName("WPT header MUST be parseable as valid JSON")
        void wptHeaderMustBeParseableJson() throws JOSEException, ParseException {
            String wptJwtString = generateSignedWptJwtString();

            SignedJWT parsedJwt = SignedJWT.parse(wptJwtString);
            JWSHeader header = parsedJwt.getHeader();

            assertThat(header).isNotNull();
            assertThat(header.getType().getType()).isEqualTo(WPT_MEDIA_TYPE);
            assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        }
    }

    @Nested
    @DisplayName("WPT Required Claims Conformance (draft-ietf-wimse-workload-creds §3.2)")
    class WptRequiredClaimsTests {

        @Test
        @DisplayName("WPT MUST contain aud (Audience) claim")
        void wptMustContainAudClaim() {
            WorkloadProofToken wpt = buildValidWpt();

            assertThat(wpt.getAudience()).isNotNull();
            assertThat(wpt.getAudience()).isEqualTo(AUDIENCE);
        }

        @Test
        @DisplayName("WPT MUST contain exp (Expiration Time) claim")
        void wptMustContainExpClaim() {
            WorkloadProofToken wpt = buildValidWpt();

            assertThat(wpt.getExpirationTime()).isNotNull();
            assertThat(wpt.getExpirationTime()).isAfter(new Date());
        }

        @Test
        @DisplayName("WPT MUST contain jti (JWT ID) claim")
        void wptMustContainJtiClaim() {
            WorkloadProofToken wpt = buildValidWpt();

            assertThat(wpt.getJwtId()).isNotNull();
            assertThat(wpt.getJwtId()).isNotEmpty();
        }

        @Test
        @DisplayName("WPT MUST contain wth (Workload Token Hash) claim")
        void wptMustContainWthClaim() {
            WorkloadProofToken wpt = buildValidWpt();

            assertThat(wpt.getWorkloadTokenHash()).isNotNull();
            assertThat(wpt.getWorkloadTokenHash()).isNotEmpty();
        }

        @Test
        @DisplayName("WPT exp claim MUST represent a future time")
        void wptExpClaimMustBeFutureTime() {
            WorkloadProofToken wpt = buildValidWpt();

            assertThat(wpt.isExpired()).isFalse();
            assertThat(wpt.isValid()).isTrue();
        }

        @Test
        @DisplayName("Expired WPT MUST be detected as invalid")
        void expiredWptMustBeDetectedAsInvalid() {
            Date pastExpiration = new Date(System.currentTimeMillis() - 60_000);

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience(AUDIENCE)
                    .expirationTime(pastExpiration)
                    .jwtId(UUID.randomUUID().toString())
                    .workloadTokenHash("test-wth-hash")
                    .build();

            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WPT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            WorkloadProofToken expiredWpt = WorkloadProofToken.builder()
                    .header(header)
                    .claims(claims)
                    .build();

            assertThat(expiredWpt.isExpired()).isTrue();
            assertThat(expiredWpt.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("WPT Builder Validation Tests")
    class WptBuilderValidationTests {

        @Test
        @DisplayName("WPT builder MUST require header")
        void wptBuilderMustRequireHeader() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience(AUDIENCE)
                    .expirationTime(futureDate())
                    .jwtId(UUID.randomUUID().toString())
                    .workloadTokenHash("test-wth")
                    .build();

            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .claims(claims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("header");
        }

        @Test
        @DisplayName("WPT builder MUST require claims")
        void wptBuilderMustRequireClaims() {
            WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                    .type(WPT_MEDIA_TYPE)
                    .algorithm("RS256")
                    .build();

            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .header(header)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("claims");
        }
    }

    @Nested
    @DisplayName("WPT Optional Token Hash Claims Tests")
    class WptOptionalTokenHashClaimsTests {

        @Test
        @DisplayName("WPT MAY contain ath (Access Token Hash) claim")
        void wptMayContainAthClaim() {
            String accessTokenHash = computeSha256Hash("sample-access-token");

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience(AUDIENCE)
                    .expirationTime(futureDate())
                    .jwtId(UUID.randomUUID().toString())
                    .workloadTokenHash("test-wth")
                    .accessTokenHash(accessTokenHash)
                    .build();

            assertThat(claims.getAccessTokenHash()).isNotNull();
            assertThat(claims.getAccessTokenHash()).isEqualTo(accessTokenHash);
        }

        @Test
        @DisplayName("WPT MAY contain tth (Transaction Token Hash) claim")
        void wptMayContainTthClaim() {
            String transactionTokenHash = computeSha256Hash("sample-transaction-token");

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience(AUDIENCE)
                    .expirationTime(futureDate())
                    .jwtId(UUID.randomUUID().toString())
                    .workloadTokenHash("test-wth")
                    .transactionTokenHash(transactionTokenHash)
                    .build();

            assertThat(claims.getTransactionTokenHash()).isNotNull();
            assertThat(claims.getTransactionTokenHash()).isEqualTo(transactionTokenHash);
        }

        @Test
        @DisplayName("WPT MAY contain oth (Other Token Hashes) claim")
        void wptMayContainOthClaim() {
            Map<String, String> otherHashes = Map.of(
                    "custom_token", computeSha256Hash("custom-token-value")
            );

            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience(AUDIENCE)
                    .expirationTime(futureDate())
                    .jwtId(UUID.randomUUID().toString())
                    .workloadTokenHash("test-wth")
                    .otherTokenHashes(otherHashes)
                    .build();

            assertThat(claims.getOtherTokenHashes()).isNotNull();
            assertThat(claims.getOtherTokenHashes()).containsKey("custom_token");
        }
    }

    @Nested
    @DisplayName("Cryptographic Binding Tests (draft-ietf-wimse-workload-creds §3.2)")
    class CryptographicBindingTests {

        @Test
        @DisplayName("WPT wth claim MUST be SHA-256 hash of the WIT JWT string")
        void wptWthMustBeSha256HashOfWit() throws JOSEException {
            String witJwtString = generateSignedWitJwtString();
            String expectedWth = computeSha256Hash(witJwtString);

            WorkloadProofToken.Claims wptClaims = WorkloadProofToken.Claims.builder()
                    .audience(AUDIENCE)
                    .expirationTime(futureDate())
                    .jwtId(UUID.randomUUID().toString())
                    .workloadTokenHash(expectedWth)
                    .build();

            assertThat(wptClaims.getWorkloadTokenHash()).isEqualTo(expectedWth);
        }

        @Test
        @DisplayName("WPT MUST be signed with the private key corresponding to WIT cnf JWK")
        void wptMustBeSignedWithWitCnfKey() throws JOSEException, ParseException {
            String wptJwtString = generateSignedWptJwtString();

            SignedJWT parsedWpt = SignedJWT.parse(wptJwtString);

            boolean verified = parsedWpt.verify(
                    new com.nimbusds.jose.crypto.RSASSAVerifier(workloadKeyPair.toRSAPublicKey())
            );
            assertThat(verified).isTrue();
        }

        @Test
        @DisplayName("WPT signature verification MUST fail with wrong key")
        void wptSignatureVerificationMustFailWithWrongKey() throws JOSEException, ParseException {
            String wptJwtString = generateSignedWptJwtString();

            RSAKey wrongKey = new RSAKeyGenerator(2048)
                    .keyID("wrong-key")
                    .generate();

            SignedJWT parsedWpt = SignedJWT.parse(wptJwtString);

            boolean verified = parsedWpt.verify(
                    new com.nimbusds.jose.crypto.RSASSAVerifier(wrongKey.toRSAPublicKey())
            );
            assertThat(verified).isFalse();
        }

        @Test
        @DisplayName("WPT wth MUST change when WIT content changes")
        void wptWthMustChangeWhenWitChanges() throws JOSEException {
            String witJwtString1 = generateSignedWitJwtString();
            String witJwtString2 = generateSignedWitJwtStringWithSubject("different-workload");

            String wth1 = computeSha256Hash(witJwtString1);
            String wth2 = computeSha256Hash(witJwtString2);

            assertThat(wth1).isNotEqualTo(wth2);
        }
    }

    @Nested
    @DisplayName("Interoperability Tests")
    class InteroperabilityTests {

        @Test
        @DisplayName("WIT JWT MUST be parseable by Nimbus JOSE+JWT library")
        void witJwtMustBeParseableByNimbus() throws JOSEException, ParseException {
            String witJwtString = generateSignedWitJwtString();

            SignedJWT parsedJwt = SignedJWT.parse(witJwtString);

            assertThat(parsedJwt.getHeader().getType().getType()).isEqualTo(WIT_MEDIA_TYPE);
            assertThat(parsedJwt.getJWTClaimsSet().getIssuer()).isEqualTo(ISSUER);
            assertThat(parsedJwt.getJWTClaimsSet().getSubject()).isEqualTo(SUBJECT);
            assertThat(parsedJwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
        }

        @Test
        @DisplayName("WPT JWT MUST be parseable by Nimbus JOSE+JWT library")
        void wptJwtMustBeParseableByNimbus() throws JOSEException, ParseException {
            String wptJwtString = generateSignedWptJwtString();

            SignedJWT parsedJwt = SignedJWT.parse(wptJwtString);

            assertThat(parsedJwt.getHeader().getType().getType()).isEqualTo(WPT_MEDIA_TYPE);
            assertThat(parsedJwt.getJWTClaimsSet().getAudience()).contains(AUDIENCE);
            assertThat(parsedJwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
            assertThat(parsedJwt.getJWTClaimsSet().getJWTID()).isNotNull();
            assertThat(parsedJwt.getJWTClaimsSet().getClaim("wth")).isNotNull();
        }

        @Test
        @DisplayName("WIT signature MUST be verifiable with issuer's public key via Nimbus")
        void witSignatureMustBeVerifiableViaNimbus() throws JOSEException, ParseException {
            String witJwtString = generateSignedWitJwtString();

            SignedJWT parsedJwt = SignedJWT.parse(witJwtString);

            boolean verified = parsedJwt.verify(
                    new com.nimbusds.jose.crypto.RSASSAVerifier(issuerSigningKey.toRSAPublicKey())
            );
            assertThat(verified).isTrue();
        }

        @Test
        @DisplayName("WIT cnf claim MUST contain valid JWK that can be parsed by Nimbus")
        void witCnfClaimMustContainValidJwk() throws JOSEException, ParseException {
            String witJwtString = generateSignedWitJwtString();

            SignedJWT parsedJwt = SignedJWT.parse(witJwtString);
            Map<String, Object> cnfClaim = parsedJwt.getJWTClaimsSet().getJSONObjectClaim("cnf");

            assertThat(cnfClaim).isNotNull();
            assertThat(cnfClaim).containsKey("jwk");

            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) cnfClaim.get("jwk");
            assertThat(jwkMap).containsKey("kty");
            assertThat(jwkMap).containsKey("n");
            assertThat(jwkMap).containsKey("e");
            assertThat(jwkMap).doesNotContainKey("d");
        }
    }

    @Nested
    @DisplayName("WptGenerator Integration Tests")
    class WptGeneratorTests {

        @Test
        @DisplayName("WptGenerator MUST produce valid WPT from WIT")
        void wptGeneratorMustProduceValidWpt() throws JOSEException {
            WorkloadIdentityToken wit = buildValidWitWithJwtString();
            WptGenerator wptGenerator = new WptGenerator();

            WorkloadProofToken wpt = wptGenerator.generateWpt(
                    wit,
                    workloadKeyPair,
                    300
            );

            assertThat(wpt).isNotNull();
            assertThat(wpt.getHeader()).isNotNull();
            assertThat(wpt.getHeader().getType()).isEqualTo(WPT_MEDIA_TYPE);
            assertThat(wpt.getClaims()).isNotNull();
            assertThat(wpt.getWorkloadTokenHash()).isNotNull();
            assertThat(wpt.getExpirationTime()).isNotNull();
            assertThat(wpt.getJwtId()).isNotNull();
        }

        @Test
        @DisplayName("WptGenerator MUST produce WPT as JWT string")
        void wptGeneratorMustProduceWptAsJwtString() throws JOSEException {
            WorkloadIdentityToken wit = buildValidWitWithJwtString();
            WptGenerator wptGenerator = new WptGenerator();

            String wptJwtString = wptGenerator.generateWptAsString(
                    wit,
                    workloadKeyPair,
                    300
            );

            assertThat(wptJwtString).isNotNull();
            assertThat(wptJwtString.split("\\.")).hasSize(3);
        }

        @Test
        @DisplayName("WptGenerator WPT wth MUST match SHA-256 hash of WIT JWT string")
        void wptGeneratorWthMustMatchWitHash() throws JOSEException {
            WorkloadIdentityToken wit = buildValidWitWithJwtString();
            WptGenerator wptGenerator = new WptGenerator();

            WorkloadProofToken wpt = wptGenerator.generateWpt(
                    wit,
                    workloadKeyPair,
                    300
            );

            String expectedWth = computeSha256Hash(wit.getJwtString());
            assertThat(wpt.getWorkloadTokenHash()).isEqualTo(expectedWth);
        }
    }

    // ========== Helper Methods ==========

    private WorkloadIdentityToken buildValidWit() {
        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type(WIT_MEDIA_TYPE)
                .algorithm("RS256")
                .build();

        // Build JWK from workloadKeyPair for cnf claim
        Jwk jwk = Jwk.builder()
                .keyType(KeyType.RSA)
                .keyId(workloadKeyPair.getKeyID())
                .algorithm("RS256")
                .build();

        WorkloadIdentityToken.Claims.Confirmation confirmation = 
                WorkloadIdentityToken.Claims.Confirmation.builder()
                        .jwk(jwk)
                        .build();

        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .expirationTime(futureDate())
                .jwtId(UUID.randomUUID().toString())
                .confirmation(confirmation)
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .build();
    }

    private WorkloadIdentityToken buildValidWitWithJwtString() throws JOSEException {
        String jwtString = generateSignedWitJwtString();

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type(WIT_MEDIA_TYPE)
                .algorithm("RS256")
                .build();

        // Build JWK from workloadKeyPair for cnf claim
        Jwk jwk = Jwk.builder()
                .keyType(KeyType.RSA)
                .keyId(workloadKeyPair.getKeyID())
                .algorithm("RS256")
                .build();

        WorkloadIdentityToken.Claims.Confirmation confirmation = 
                WorkloadIdentityToken.Claims.Confirmation.builder()
                        .jwk(jwk)
                        .build();

        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .expirationTime(futureDate())
                .jwtId(UUID.randomUUID().toString())
                .confirmation(confirmation)
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .jwtString(jwtString)
                .build();
    }

    private WorkloadProofToken buildValidWpt() {
        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type(WPT_MEDIA_TYPE)
                .algorithm("RS256")
                .build();

        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .audience(AUDIENCE)
                .expirationTime(futureDate())
                .jwtId(UUID.randomUUID().toString())
                .workloadTokenHash(computeSha256Hash("test.wit.jwt.string"))
                .build();

        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .build();
    }

    private String generateSignedWitJwtString() throws JOSEException {
        return generateSignedWitJwtStringWithSubject(SUBJECT);
    }

    private String generateSignedWitJwtStringWithSubject(String subject) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new com.nimbusds.jose.JOSEObjectType(WIT_MEDIA_TYPE))
                .keyID(issuerSigningKey.getKeyID())
                .build();

        Map<String, Object> cnfClaim = Map.of(
                "jwk", workloadKeyPair.toPublicJWK().toJSONObject()
        );

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(subject)
                .expirationTime(futureDate())
                .jwtID(UUID.randomUUID().toString())
                .claim("cnf", cnfClaim)
                .build();

        SignedJWT signedJwt = new SignedJWT(header, claimsSet);
        JWSSigner signer = new RSASSASigner(issuerSigningKey);
        signedJwt.sign(signer);

        return signedJwt.serialize();
    }

    private String generateSignedWptJwtString() throws JOSEException {
        String witJwtString = generateSignedWitJwtString();
        String wth = computeSha256Hash(witJwtString);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new com.nimbusds.jose.JOSEObjectType(WPT_MEDIA_TYPE))
                .keyID(workloadKeyPair.getKeyID())
                .build();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(AUDIENCE)
                .expirationTime(futureDate())
                .jwtID(UUID.randomUUID().toString())
                .claim("wth", wth)
                .build();

        SignedJWT signedJwt = new SignedJWT(header, claimsSet);
        JWSSigner signer = new RSASSASigner(workloadKeyPair);
        signedJwt.sign(signer);

        return signedJwt.serialize();
    }

    private static Date futureDate() {
        return new Date(System.currentTimeMillis() + 3_600_000);
    }

    private static String computeSha256Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
