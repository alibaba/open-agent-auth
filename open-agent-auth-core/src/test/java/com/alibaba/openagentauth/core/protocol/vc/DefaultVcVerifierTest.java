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
package com.alibaba.openagentauth.core.protocol.vc;

import com.alibaba.openagentauth.core.exception.workload.VcVerificationException;
import com.alibaba.openagentauth.core.model.evidence.Proof;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.crypto.jwk.JwksProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DefaultVcVerifier}.
 * <p>
 * These tests validate the verification functionality according to the
 * draft-liu-agent-operation-authorization-01 specification requirements:
 * </p>
 * <ul>
 *   <li>JWT structure and algorithm validation</li>
 *   <li>Signature verification using JWKS</li>
 *   <li>Required claims validation (type, credentialSubject, issuer, jti)</li>
 *   <li>Time-based validation (expiration, not-before, max age)</li>
 *   <li>Issuer validation</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization-01/">draft-liu-agent-operation-authorization-01</a>
 */
class DefaultVcVerifierTest {

    private static final String TEST_ISSUER = "https://client.myassistant.example";
    private static final String TEST_KEY_ID = "key-01";
    private static final String TEST_JTI = "pt-001";
    private static final String TEST_SUBJECT = "user_12345";

    private RSAKey rsaKey;
    private DefaultVcSigner signer;
    private DefaultVcVerifier verifier;
    private JwksProvider jwksProvider;

    @BeforeEach
    void setUp() throws Exception {
        // Generate RSA key pair for testing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        rsaKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        // Create signer
        signer = new DefaultVcSigner(rsaKey, TEST_KEY_ID, TEST_ISSUER);
        
        // Create JWKS provider for verification
        jwksProvider = new StaticJwksProvider(rsaKey);
        
        // Create verifier
        verifier = new DefaultVcVerifier(jwksProvider);
    }

    @Test
    void testVerifyValidCredential() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        String signedJwt = signer.sign(credential);

        // Act
        VerifiableCredential verifiedCredential = verifier.verify(signedJwt);

        // Assert
        assertNotNull(verifiedCredential, "Verified credential should not be null");
        assertEquals(TEST_JTI, verifiedCredential.getJti(), "JTI should match");
        assertEquals(TEST_ISSUER, verifiedCredential.getIss(), "Issuer should match");
        assertEquals(TEST_SUBJECT, verifiedCredential.getSub(), "Subject should match");
        assertEquals("VerifiableCredential", verifiedCredential.getType(), "Type should be VerifiableCredential");
    }

    @Test
    void testVerifyWithNullJwt() {
        // Act & Assert
        assertThrows(
                IllegalArgumentException.class,
                () -> verifier.verify(null),
                "Should throw NullPointerException for null JWT"
        );
    }

    @Test
    void testVerifyWithInvalidSignature() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        String signedJwt = signer.sign(credential);
        
        // Tamper with the signature
        String[] parts = signedJwt.split("\\.");
        String tamperedJwt = parts[0] + "." + parts[1] + "." + "tamperedSignature";

        // Act & Assert
        assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(tamperedJwt),
                "Should throw exception for invalid signature"
        );
    }

    @Test
    void testVerifyWithExpiredCredential() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.minusSeconds(3600); // Expired 1 hour ago
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for expired credential"
        );
        assertEquals("VC-EXPIRED", exception.getVcErrorCode(), "VC error code should be VC-EXPIRED");
    }

    @Test
    void testVerifyWithCredentialNotYetValid() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant issuedAt = now.plusSeconds(3600); // Not valid until 1 hour from now
        Instant expiration = issuedAt.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(issuedAt)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for credential not yet valid"
        );
        assertEquals("VC-NOT-YET-VALID", exception.getVcErrorCode(), "VC error code should be VC-NOT-YET-VALID");
    }

    @Test
    void testVerifyWithCredentialExceedsMaxAge() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant issuedAt = now.minusSeconds(86401); // Issued more than 24 hours ago
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(issuedAt)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for credential exceeding max age"
        );
        assertEquals("VC-EXCEEDS-MAX-AGE", exception.getVcErrorCode(), "VC error code should be VC-EXCEEDS-MAX-AGE");
    }

    @Test
    void testVerifyWithMissingTypeClaim() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type(null) // Missing type
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for missing type claim"
        );
        assertEquals("VC-MISSING-CLAIM", exception.getVcErrorCode(), "VC error code should be VC-MISSING-CLAIM");
    }

    @Test
    void testVerifyWithInvalidTypeClaim() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("InvalidType") // Invalid type
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for invalid type claim"
        );
        assertEquals("VC-INVALID-TYPE", exception.getVcErrorCode(), "VC error code should be VC-INVALID-TYPE");
    }

    @Test
    void testVerifyWithMissingCredentialSubject() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(null) // Missing credential subject
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for missing credential subject"
        );
        assertEquals("VC-MISSING-SUBJECT", exception.getVcErrorCode(), "VC error code should be VC-MISSING-SUBJECT");
    }

    @Test
    void testVerifyWithMissingIssuer() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(null) // Missing issuer
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for missing issuer"
        );
        assertEquals("VC-MISSING-ISSUER", exception.getVcErrorCode(), "VC error code should be VC-MISSING-ISSUER");
    }

    @Test
    void testVerifyWithMissingJti() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(null) // Missing JTI
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        String signedJwt = signer.sign(credential);

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for missing JTI"
        );
        assertEquals("VC-MISSING-JTI", exception.getVcErrorCode(), "VC error code should be VC-MISSING-JTI");
    }

    @Test
    void testVerifyWithExpectedIssuer() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        String signedJwt = signer.sign(credential);
        
        verifier.setExpectedIssuer(TEST_ISSUER);

        // Act
        VerifiableCredential verifiedCredential = verifier.verify(signedJwt);

        // Assert
        assertNotNull(verifiedCredential, "Verified credential should not be null");
        assertEquals(TEST_ISSUER, verifiedCredential.getIss(), "Issuer should match");
    }

    @Test
    void testVerifyWithMismatchedIssuer() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        String signedJwt = signer.sign(credential);
        
        verifier.setExpectedIssuer("https://different-issuer.example");

        // Act & Assert
        VcVerificationException exception = assertThrows(
                VcVerificationException.class,
                () -> verifier.verify(signedJwt),
                "Should throw exception for mismatched issuer"
        );
        assertEquals("VC-INVALID-ISSUER", exception.getVcErrorCode(), "VC error code should be VC-INVALID-ISSUER");
    }

    @Test
    void testConstructorWithNullJwksProvider() {
        // Act & Assert
        assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultVcVerifier(null),
                "Should throw NullPointerException for null JWKS provider"
        );
    }

    @Test
    void testGetExpectedIssuer() {
        // Act
        verifier.setExpectedIssuer(TEST_ISSUER);
        String expectedIssuer = verifier.getExpectedIssuer();

        // Assert
        assertEquals(TEST_ISSUER, expectedIssuer, "Expected issuer should match");
    }

    @Test
    void testGetPolicy() {
        // Act
        VcVerificationPolicy policy = verifier.getPolicy();

        // Assert
        assertNotNull(policy, "Policy should not be null");
    }

    @Test
    void testVerifyWithCustomPolicy() throws Exception {
        // Arrange - Note: VcVerificationPolicy doesn't have setMaxAge method
        // This test is simplified to verify the custom policy is used
        VcVerificationPolicy customPolicy = new VcVerificationPolicy();
        customPolicy.setExpectedIssuer(TEST_ISSUER);

        DefaultVcVerifier customVerifier = new DefaultVcVerifier(jwksProvider, customPolicy);

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);

        VerifiableCredential credential = createTestCredential(now, expiration);
        String signedJwt = signer.sign(credential);

        // Act
        VerifiableCredential verifiedCredential = customVerifier.verify(signedJwt);

        // Assert
        assertNotNull(verifiedCredential, "Credential should be verified with custom policy");
        assertEquals(TEST_ISSUER, verifiedCredential.getIss(), "Issuer should match expected issuer");
    }

    /**
     * Creates a test VerifiableCredential with all required fields.
     */
    private VerifiableCredential createTestCredential(Instant now, Instant expiration) {
        return VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
    }

    /**
     * Creates a test UserInputEvidence.
     */
    private UserInputEvidence createTestEvidence(Instant now) {
        return UserInputEvidence.builder()
                .type("UserInputEvidence")
                .prompt("Buy something cheap on Nov 11 night")
                .timestamp(now)
                .channel("voice")
                .deviceFingerprint("dfp_abc123")
                .build();
    }

    /**
     * Creates a test Proof.
     */
    private Proof createTestProof(Instant now) {
        return new Proof.Builder()
                .type("JwtProof2020")
                .created(now)
                .verificationMethod(TEST_ISSUER + "/#key-01")
                .build();
    }

    /**
     * Simple static JWKS provider for testing purposes.
     */
    private static class StaticJwksProvider implements JwksProvider {
        private final RSAKey publicKey;

        StaticJwksProvider(RSAKey key) {
            this.publicKey = key.toPublicJWK();
        }

        @Override
        public com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext> getJwkSource() {
            return new com.nimbusds.jose.jwk.source.JWKSource<>() {
                @Override
                public java.util.List<com.nimbusds.jose.jwk.JWK> get(
                        com.nimbusds.jose.jwk.JWKSelector selector,
                        com.nimbusds.jose.proc.SecurityContext context) {
                    // Return all keys if no specific key ID is requested
                    if (selector.getMatcher() == null) {
                        return java.util.Collections.singletonList(publicKey);
                    }
                    // Check if the key ID matches
                    String keyId = publicKey.getKeyID();
                    if (keyId != null) {
                        return java.util.Collections.singletonList(publicKey);
                    }
                    return java.util.Collections.emptyList();
                }
            };
        }

        @Override
        public JWKSet getJwkSet() throws IOException {
            return new JWKSet(publicKey);
        }

        @Override
        public void refresh() throws IOException {
            // No-op for static provider
        }
    }
}
