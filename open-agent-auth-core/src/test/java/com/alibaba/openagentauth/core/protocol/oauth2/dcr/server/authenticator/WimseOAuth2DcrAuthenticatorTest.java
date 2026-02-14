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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.authenticator;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitConstants;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
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

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WimseOAuth2DcrAuthenticator}.
 * <p>
 * Tests verify compliance with OAuth 2.0 Dynamic Client Registration (RFC 7591)
 * and WIMSE Workload Identity Credentials (draft-ietf-wimse-workload-creds) protocols.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>WIMSE WIT signature verification</li>
 *   <li>WIT claims validation (iss, sub, exp, cnf)</li>
 *   <li>Trust domain validation</li>
 *   <li>DCR request authentication</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
@DisplayName("WIMSE DCR Authenticator Tests - RFC 7591 + WIMSE")
class WimseOAuth2DcrAuthenticatorTest {

    private WimseOAuth2DcrAuthenticator authenticator;
    private RSAKey signingKey;
    private RSAKey verificationKey;
    private ECKey wptPublicKey;
    private TrustDomain trustDomain;
    private WitGenerator witGenerator;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for WIT signing (as per WIMSE specification)
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        signingKey = rsaKeyGenerator.keyID("wit-signing-key").generate();
        verificationKey = signingKey.toPublicJWK();

        // Generate EC key pair for WPT (Workload Proof Token)
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(Curve.P_256);
        wptPublicKey = ecKeyGenerator.keyID("wpt-key").generate().toPublicJWK();

        trustDomain = new TrustDomain("wimse://example.com");
        authenticator = new WimseOAuth2DcrAuthenticator(verificationKey, trustDomain);
        witGenerator = new WitGenerator(signingKey, trustDomain, JWSAlgorithm.RS256);
    }

    @Nested
    @DisplayName("Constructor Validation - RFC 7591 Section 3.2.2")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when verification key is null")
        void shouldThrowExceptionWhenVerificationKeyIsNull() {
            assertThatThrownBy(() -> new WimseOAuth2DcrAuthenticator(null, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Verification key cannot be null");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when trust domain is null")
        void shouldThrowExceptionWhenTrustDomainIsNull() {
            assertThatThrownBy(() -> new WimseOAuth2DcrAuthenticator(verificationKey, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Trust domain cannot be null");
        }

        @Test
        @DisplayName("Should create authenticator successfully with valid parameters")
        void shouldCreateAuthenticatorSuccessfully() {
            assertThat(authenticator).isNotNull();
        }

        @Test
        @DisplayName("Should return correct authentication method")
        void shouldReturnCorrectAuthenticationMethod() {
            assertThat(authenticator.getAuthenticationMethod()).isEqualTo("private_key_jwt");
        }
    }

    @Nested
    @DisplayName("Authentication - Happy Path - RFC 7591 Section 3")
    class AuthenticationHappyPathTests {

        @Test
        @DisplayName("Should authenticate valid WIT successfully")
        void shouldAuthenticateValidWitSuccessfully() throws Exception {
            // Given
            DcrRequest request = createDcrRequestWithValidWit();

            // When
            String subject = authenticator.authenticate(request);

            // Then
            assertThat(subject).isEqualTo("agent-001");
        }

        @Test
        @DisplayName("Should authenticate WIT with correct trust domain")
        void shouldAuthenticateWitWithCorrectTrustDomain() throws Exception {
            // Given
            DcrRequest request = createDcrRequestWithValidWit();

            // When
            String subject = authenticator.authenticate(request);

            // Then
            assertThat(subject).isNotNull();
        }

        @Test
        @DisplayName("Should verify canAuthenticate returns true for valid request")
        void shouldVerifyCanAuthenticateReturnsTrueForValidRequest() throws Exception {
            // Given
            DcrRequest request = createDcrRequestWithValidWit();

            // When
            boolean canAuthenticate = authenticator.canAuthenticate(request);

            // Then
            assertThat(canAuthenticate).isTrue();
        }
    }

    @Nested
    @DisplayName("Authentication - WIT Validation - WIMSE Protocol")
    class WITValidationTests {

        @Test
        @DisplayName("Should reject request without WIT")
        void shouldRejectRequestWithoutWit() {
            // Given
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When & Then
            assertThatThrownBy(() -> authenticator.authenticate(request))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("WIT is required for WIMSE authentication")
                    .satisfies(e -> {
                        DcrException ex = (DcrException) e;
                        assertThat(ex.getRfcErrorCode()).isEqualTo("invalid_client_metadata");
                        assertThat(ex.getStatusCode()).isEqualTo(400);
                    });
        }

        @Test
        @DisplayName("Should reject request with expired WIT")
        void shouldRejectRequestWithExpiredWit() throws Exception {
            // Given
            String expiredWit = createExpiredWit();
            DcrRequest request = createDcrRequestWithWit(expiredWit);

            // When & Then
            assertThatThrownBy(() -> authenticator.authenticate(request))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("WIT validation failed")
                    .satisfies(e -> {
                        DcrException ex = (DcrException) e;
                        assertThat(ex.getRfcErrorCode()).isEqualTo("invalid_client_metadata");
                        assertThat(ex.getStatusCode()).isEqualTo(400);
                    });
        }

        @Test
        @DisplayName("Should reject request with invalid WIT format")
        void shouldRejectRequestWithInvalidWitFormat() {
            // Given
            // Use a string that cannot be parsed as JWT (no dot separators)
            DcrRequest request = createDcrRequestWithWit("invalidwitstring");

            // When & Then
            assertThatThrownBy(() -> authenticator.authenticate(request))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("Invalid WIT format")
                    .satisfies(e -> {
                        DcrException ex = (DcrException) e;
                        assertThat(ex.getRfcErrorCode()).isEqualTo("invalid_client_metadata");
                        assertThat(ex.getStatusCode()).isEqualTo(400);
                    });
        }

        @Test
        @DisplayName("Should reject request with wrong trust domain")
        void shouldRejectRequestWithWrongTrustDomain() throws Exception {
            // Given
            String wrongDomainWit = createWitWithWrongTrustDomain();
            DcrRequest request = createDcrRequestWithWit(wrongDomainWit);

            // When & Then
            assertThatThrownBy(() -> authenticator.authenticate(request))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("WIT validation failed")
                    .satisfies(e -> {
                        DcrException ex = (DcrException) e;
                        assertThat(ex.getRfcErrorCode()).isEqualTo("invalid_client_metadata");
                        assertThat(ex.getStatusCode()).isEqualTo(400);
                    });
        }

        @Test
        @DisplayName("Should reject request with invalid WIT signature")
        void shouldRejectRequestWithInvalidWitSignature() throws Exception {
            // Given
            String invalidSignatureWit = createWitWithInvalidSignature();
            DcrRequest request = createDcrRequestWithWit(invalidSignatureWit);

            // When & Then
            assertThatThrownBy(() -> authenticator.authenticate(request))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("WIT validation failed")
                    .satisfies(e -> {
                        DcrException ex = (DcrException) e;
                        assertThat(ex.getRfcErrorCode()).isEqualTo("invalid_client_metadata");
                        assertThat(ex.getStatusCode()).isEqualTo(400);
                    });
        }
    }

    @Nested
    @DisplayName("canAuthenticate - RFC 7591 Section 3.1")
    class CanAuthenticateTests {

        @Test
        @DisplayName("Should return true when WIT is present in request")
        void shouldReturnTrueWhenWitIsPresent() throws Exception {
            // Given
            DcrRequest request = createDcrRequestWithValidWit();

            // When
            boolean canAuthenticate = authenticator.canAuthenticate(request);

            // Then
            assertThat(canAuthenticate).isTrue();
        }

        @Test
        @DisplayName("Should return false when WIT is not present in request")
        void shouldReturnFalseWhenWitIsNotPresent() {
            // Given
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When
            boolean canAuthenticate = authenticator.canAuthenticate(request);

            // Then
            assertThat(canAuthenticate).isFalse();
        }

        @Test
        @DisplayName("Should return false when additional parameters are null")
        void shouldReturnFalseWhenAdditionalParametersAreNull() {
            // Given
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(null)
                    .build();

            // When
            boolean canAuthenticate = authenticator.canAuthenticate(request);

            // Then
            assertThat(canAuthenticate).isFalse();
        }

        @Test
        @DisplayName("Should return false when WIT parameter is empty string")
        void shouldReturnFalseWhenWitParameterIsEmpty() {
            // Given
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "");
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(additionalParams)
                    .build();

            // When
            boolean canAuthenticate = authenticator.canAuthenticate(request);

            // Then
            assertThat(canAuthenticate).isFalse();
        }
    }

    @Nested
    @DisplayName("Input Validation - RFC 7591 Section 3.2.2")
    class InputValidationTests {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> authenticator.authenticate(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("DCR request");
        }

        @Test
        @DisplayName("Should throw exception when canAuthenticate is called with null")
        void shouldThrowExceptionWhenCanAuthenticateIsCalledWithNull() {
            assertThatThrownBy(() -> authenticator.canAuthenticate(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("DCR request");
        }
    }

    // Helper methods

    private DcrRequest createDcrRequestWithValidWit() throws JOSEException {
        String wit = witGenerator.generateWitAsString(
                "agent-001",
                wptPublicKey.toJSONString(),
                3600
        );
        return createDcrRequestWithWit(wit);
    }

    private DcrRequest createDcrRequestWithWit(String wit) {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(WitConstants.WIT_PARAM, wit);

        return DcrRequest.builder()
                .redirectUris(List.of("https://example.com/callback"))
                .clientName("Test Client")
                .tokenEndpointAuthMethod("private_key_jwt")
                .additionalParameters(additionalParams)
                .build();
    }

    private String createExpiredWit() throws Exception {
        // Create a WIT that expired in the past
        // We need to manually construct the JWT to set expiration time to the past
        // because WitGenerator requires positive expiration seconds

        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", wptPublicKey.toJSONObject());

        // Set expiration time to 1 hour ago
        Instant expirationTime = Instant.now().minusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustDomain.getDomainId())
                .subject("agent-expired")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("cnf", cnfClaim)
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        signedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String createWitWithWrongTrustDomain() throws JOSEException {
        // Create a WIT with a different trust domain
        TrustDomain wrongDomain = new TrustDomain("wimse://wrong-domain.com");
        WitGenerator wrongGenerator = new WitGenerator(signingKey, wrongDomain, JWSAlgorithm.RS256);

        return wrongGenerator.generateWitAsString(
                "agent-001",
                wptPublicKey.toJSONString(),
                3600
        );
    }

    private String createWitWithInvalidSignature() throws Exception {
        // Create a valid WIT and then tamper with the signature
        String validWit = witGenerator.generateWitAsString(
                "agent-001",
                wptPublicKey.toJSONString(),
                3600
        );

        // Tamper with the signature
        String[] parts = validWit.split("\\.");
        if (parts.length == 3) {
            String signature = parts[2];
            String tamperedSignature = signature.replace('A', 'B').replace('a', 'b');
            return parts[0] + "." + parts[1] + "." + tamperedSignature;
        }
        return validWit;
    }
}
