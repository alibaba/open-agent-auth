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
package com.alibaba.openagentauth.core.crypto.verify;

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SignatureVerificationUtils}.
 *
 * @since 1.0
 */
@DisplayName("SignatureVerificationUtils Tests")
class SignatureVerificationUtilsTest {

    private static final String VERIFICATION_KEY_ID = "test-key";

    private RSAKey rsaKey;
    private ECKey ecKey;

    @BeforeEach
    void setUp() throws JOSEException {
        rsaKey = new RSAKeyGenerator(2048).keyID("rsa-key").generate();
        ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec-key").generate();
    }

    @Nested
    @DisplayName("verifySignature Tests")
    class VerifySignatureTests {

        @Test
        @DisplayName("Should verify valid RSA signature")
        void shouldVerifyValidRsaSignature() throws Exception {
            SignedJWT signedJwt = createSignedJwt(JWSAlgorithm.RS256, new RSASSASigner(rsaKey), rsaKey.getKeyID());

            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString())).thenReturn(rsaKey.toPublicJWK());

            boolean result = SignatureVerificationUtils.verifySignature(signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should verify valid EC signature")
        void shouldVerifyValidEcSignature() throws Exception {
            SignedJWT signedJwt = createSignedJwt(JWSAlgorithm.ES256, new ECDSASigner(ecKey), ecKey.getKeyID());

            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString())).thenReturn(ecKey.toPublicJWK());

            boolean result = SignatureVerificationUtils.verifySignature(signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false for invalid signature")
        void shouldReturnFalseForInvalidSignature() throws Exception {
            SignedJWT signedJwt = createSignedJwt(JWSAlgorithm.RS256, new RSASSASigner(rsaKey), rsaKey.getKeyID());

            // Use a different RSA key for verification
            RSAKey differentKey = new RSAKeyGenerator(2048).keyID("different-key").generate();
            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString())).thenReturn(differentKey.toPublicJWK());

            boolean result = SignatureVerificationUtils.verifySignature(signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when KeyManager throws exception")
        void shouldReturnFalseWhenKeyManagerThrowsException() throws Exception {
            SignedJWT signedJwt = createSignedJwt(JWSAlgorithm.RS256, new RSASSASigner(rsaKey), rsaKey.getKeyID());

            KeyManager keyManager = mock(KeyManager.class);
            when(keyManager.resolveVerificationKey(anyString()))
                    .thenThrow(new KeyManagementException("Key not found"));

            boolean result = SignatureVerificationUtils.verifySignature(signedJwt, keyManager, VERIFICATION_KEY_ID);

            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("createVerifier Tests")
    class CreateVerifierTests {

        @Test
        @DisplayName("Should create RSA verifier from RSA key")
        void shouldCreateRsaVerifier() throws JOSEException {
            JWSVerifier verifier = SignatureVerificationUtils.createVerifier(rsaKey.toPublicJWK());

            assertThat(verifier).isNotNull();
            assertThat(verifier.supportedJWSAlgorithms()).contains(JWSAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should create EC verifier from EC key")
        void shouldCreateEcVerifier() throws JOSEException {
            JWSVerifier verifier = SignatureVerificationUtils.createVerifier(ecKey.toPublicJWK());

            assertThat(verifier).isNotNull();
            assertThat(verifier.supportedJWSAlgorithms()).contains(JWSAlgorithm.ES256);
        }

        @Test
        @DisplayName("Should throw exception for unsupported key type")
        void shouldThrowExceptionForUnsupportedKeyType() throws JOSEException {
            OctetSequenceKey octKey = new OctetSequenceKeyGenerator(256).keyID("oct-key").generate();

            assertThatThrownBy(() -> SignatureVerificationUtils.createVerifier(octKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Unsupported JWK type");
        }
    }

    @Nested
    @DisplayName("isSupportedAlgorithm Tests")
    class IsSupportedAlgorithmTests {

        @Test
        @DisplayName("Should return true for RSA algorithms")
        void shouldReturnTrueForRsaAlgorithms() {
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.RS256)).isTrue();
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.RS384)).isTrue();
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.RS512)).isTrue();
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.PS256)).isTrue();
        }

        @Test
        @DisplayName("Should return true for EC algorithms")
        void shouldReturnTrueForEcAlgorithms() {
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.ES256)).isTrue();
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.ES384)).isTrue();
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(JWSAlgorithm.ES512)).isTrue();
        }

        @Test
        @DisplayName("Should return false for unsupported algorithms")
        void shouldReturnFalseForUnsupportedAlgorithms() {
            assertThat(SignatureVerificationUtils.isSupportedAlgorithm(new JWSAlgorithm("none"))).isFalse();
        }
    }

    private SignedJWT createSignedJwt(JWSAlgorithm algorithm, com.nimbusds.jose.JWSSigner signer, String keyId)
            throws JOSEException {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://example.com")
                .subject("test-subject")
                .expirationTime(new Date(System.currentTimeMillis() + 3600_000))
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(algorithm).keyID(keyId).build(),
                claimsSet
        );
        signedJwt.sign(signer);
        return signedJwt;
    }
}
