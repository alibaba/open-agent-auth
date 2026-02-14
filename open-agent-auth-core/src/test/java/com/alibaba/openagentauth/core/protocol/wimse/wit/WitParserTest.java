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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for {@link WitParser}.
 * Tests verify compliance with WIMSE WIT protocol specification:
 * https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/
 */
@DisplayName("WIT Parser Tests - draft-ietf-wimse-workload-creds")
class WitParserTest {

    private WitParser witParser;
    private RSAKey signingKey;
    private ECKey wptPublicKey;

    @BeforeEach
    void setUp() throws JOSEException {
        witParser = new WitParser();
        
        // Generate RSA key pair for WIT signing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        signingKey = rsaKeyGenerator.keyID("wit-signing-key").generate();
        
        // Generate EC key pair for WPT
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(Curve.P_256);
        wptPublicKey = ecKeyGenerator.keyID("wpt-key").generate().toPublicJWK();
    }

    @Nested
    @DisplayName("WIT Parsing - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should parse valid WIT with all claims")
        void shouldParseValidWitWithAllClaims() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithAllClaims();

            // When
            WorkloadIdentityToken wit = witParser.parse(signedJwt);

            // Then
            assertThat(wit).isNotNull();
            assertThat(wit.getSubject()).isEqualTo("agent-001");
            assertThat(wit.getIssuer()).isEqualTo("wimse://example.com");
            assertThat(wit.getExpirationTime()).isNotNull();
            assertThat(wit.getJwtId()).isNotNull();
            assertThat(wit.getConfirmation()).isNotNull();
        }

        @Test
        @DisplayName("Should parse cnf claim with jwk")
        void shouldParseCnfClaimWithJwk() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithCnfJwk();

            // When
            WorkloadIdentityToken wit = witParser.parse(signedJwt);

            // Then
            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getConfirmation().getJwk()).isNotNull();
            assertThat(wit.getConfirmation().getJwk().getKeyType()).isEqualTo(Jwk.KeyType.EC);
            assertThat(wit.getConfirmation().getJwk().getAlgorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should parse header correctly")
        void shouldParseHeaderCorrectly() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithAllClaims();

            // When
            WorkloadIdentityToken wit = witParser.parse(signedJwt);

            // Then
            assertThat(wit.getHeader()).isNotNull();
            assertThat(wit.getHeader().getType()).isEqualTo("wit+jwt");
            assertThat(wit.getHeader().getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should parse WIT without optional claims")
        void shouldParseWitWithoutOptionalClaims() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithRequiredClaimsOnly();

            // When
            WorkloadIdentityToken wit = witParser.parse(signedJwt);

            // Then
            assertThat(wit).isNotNull();
            assertThat(wit.getSubject()).isNotNull();
            assertThat(wit.getExpirationTime()).isNotNull();
            assertThat(wit.getConfirmation()).isNotNull();
            // Optional claims may be null
            assertThat(wit.getIssuer()).isNull();
            assertThat(wit.getJwtId()).isNull();
        }
    }

    @Nested
    @DisplayName("WIT Parsing - Error Handling")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when signedJwt is null")
        void shouldThrowExceptionWhenSignedJwtIsNull() {
            // When & Then
            assertThatThrownBy(() -> witParser.parse(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signed JWT cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when cnf claim missing jwk")
        void shouldThrowExceptionWhenCnfClaimMissingJwk() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithCnfMissingJwk();

            // When & Then
            assertThatThrownBy(() -> witParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("cnf claim missing required 'jwk' field");
        }

        @Test
        @DisplayName("Should throw exception when cnf.jwk is invalid")
        void shouldThrowExceptionWhenCnfJwkIsInvalid() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithInvalidCnfJwk();

            // When & Then
            assertThatThrownBy(() -> witParser.parse(signedJwt))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("Failed to parse cnf.jwk claim");
        }

        @Test
        @DisplayName("Should parse WIT without cnf claim")
        void shouldParseWitWithoutCnfClaim() throws Exception {
            // Given
            SignedJWT signedJwt = createSignedJwtWithoutCnf();

            // When
            WorkloadIdentityToken wit = witParser.parse(signedJwt);

            // Then
            assertThat(wit).isNotNull();
            assertThat(wit.getConfirmation()).isNull();
        }
    }

    /**
     * Creates a signed JWT with all claims.
     */
    private SignedJWT createSignedJwtWithAllClaims() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", createJwkMap());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("wimse://example.com")
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID("test-jti-001")
                .claim("cnf", cnfClaim)
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Creates a signed JWT with cnf.jwk.
     */
    private SignedJWT createSignedJwtWithCnfJwk() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", createJwkMap());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("cnf", cnfClaim)
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Creates a signed JWT with required claims only.
     */
    private SignedJWT createSignedJwtWithRequiredClaimsOnly() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", createJwkMap());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("cnf", cnfClaim)
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Creates a signed JWT with cnf claim missing jwk.
     */
    private SignedJWT createSignedJwtWithCnfMissingJwk() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        // Missing jwk field

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("cnf", cnfClaim)
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Creates a signed JWT with invalid cnf.jwk.
     */
    private SignedJWT createSignedJwtWithInvalidCnfJwk() throws Exception {
        Map<String, Object> cnfClaim = new HashMap<>();
        Map<String, Object> invalidJwk = new HashMap<>();
        invalidJwk.put("kty", "INVALID");
        cnfClaim.put("jwk", invalidJwk);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("cnf", cnfClaim)
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Creates a signed JWT without cnf claim.
     */
    private SignedJWT createSignedJwtWithoutCnf() throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Creates a JWK map from the test public key.
     * <p>
     * Ensures the JWK includes the algorithm field (alg) as required by WIMSE protocol.
     * According to draft-ietf-wimse-workload-creds, the cnf.jwk should specify the algorithm
     * used for WPT verification.
     * </p>
     */
    private Map<String, Object> createJwkMap() throws Exception {
        Map<String, Object> jwkMap = wptPublicKey.toJSONObject();
        // Ensure the algorithm field is present
        // For EC P-256 keys, the algorithm should be ES256
        jwkMap.put("alg", "ES256");
        return jwkMap;
    }

    /**
     * Signs a JWT claims set.
     */
    private SignedJWT signJwt(JWTClaimsSet claimsSet) throws Exception {
        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );
        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt;
    }
}
