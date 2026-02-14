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

import com.alibaba.openagentauth.core.model.evidence.Proof;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.crypto.jwk.JwksProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DefaultVcSigner}.
 * <p>
 * These tests validate the signing functionality according to the
 * draft-liu-agent-operation-authorization-01 specification requirements:
 * </p>
 * <ul>
 *   <li>RS256 algorithm usage for signing</li>
 *   <li>JWT header includes key ID (kid) for verification</li>
 *   <li>Proper encoding of Verifiable Credential claims</li>
 *   <li>Cryptographic signature integrity</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization-01/">draft-liu-agent-operation-authorization-01</a>
 */
class DefaultVcSignerTest {

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
    void testSignValidCredential() throws Exception {
        // Arrange
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);
        
        UserInputEvidence evidence = UserInputEvidence.builder()
                .type("UserInputEvidence")
                .prompt("Buy something cheap on Nov 11 night")
                .timestamp(now)
                .channel("voice")
                .deviceFingerprint("dfp_abc123")
                .build();
        
        Proof proof = new Proof.Builder()
                .type("JwtProof2020")
                .created(now)
                .verificationMethod(TEST_ISSUER + "/#key-01")
                .build();
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(evidence)
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(proof)
                .build();

        // Act
        String signedJwt = signer.sign(credential);

        // Assert
        assertNotNull(signedJwt, "Signed JWT should not be null");
        assertFalse(signedJwt.isEmpty(), "Signed JWT should not be empty");
        
        // Verify JWT structure (header.payload.signature)
        String[] parts = signedJwt.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify the signed credential can be verified
        VerifiableCredential verifiedCredential = verifier.verify(signedJwt);
        assertNotNull(verifiedCredential, "Verified credential should not be null");
        assertEquals(TEST_JTI, verifiedCredential.getJti(), "JTI should match");
        assertEquals(TEST_ISSUER, verifiedCredential.getIss(), "Issuer should match");
        assertEquals(TEST_SUBJECT, verifiedCredential.getSub(), "Subject should match");
        assertEquals("VerifiableCredential", verifiedCredential.getType(), "Type should be VerifiableCredential");
    }

    @Test
    void testSignWithNullCredential() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> signer.sign(null),
                "Should throw NullPointerException for null credential"
        );
        assertTrue(exception.getMessage().contains("Credential"), "Error message should mention credential");
    }

    @Test
    void testConstructorWithNullSigningKey() {
        // Act & Assert - Test with RSAKey constructor
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultVcSigner((RSAKey) null, TEST_KEY_ID, TEST_ISSUER),
                "Should throw NullPointerException for null signing key"
        );
        assertTrue(exception.getMessage().contains("Signing key"), "Error message should mention signing key");
    }

    @Test
    void testConstructorWithNullKeyId() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultVcSigner(rsaKey, null, TEST_ISSUER),
                "Should throw NullPointerException for null key ID"
        );
        assertTrue(exception.getMessage().contains("Key ID"), "Error message should mention key ID");
    }

    @Test
    void testConstructorWithNullIssuer() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> new DefaultVcSigner(rsaKey, TEST_KEY_ID, null),
                "Should throw NullPointerException for null issuer"
        );
        assertTrue(exception.getMessage().contains("Issuer"), "Error message should mention issuer");
    }

    @Test
    void testGetKeyId() {
        // Act
        String keyId = signer.getKeyId();

        // Assert
        assertEquals(TEST_KEY_ID, keyId, "Key ID should match");
    }

    @Test
    void testGetIssuer() {
        // Act
        String issuer = signer.getIssuer();

        // Assert
        assertEquals(TEST_ISSUER, issuer, "Issuer should match");
    }

    @Test
    void testGetSigningKey() throws JOSEException {
        // Act
        JWK signingKey = signer.getSigningKey();

        // Assert
        assertNotNull(signingKey, "Signing key should not be null");
        assertEquals(rsaKey.getKeyID(), signingKey.getKeyID(), "Key ID should match");
        assertTrue(signingKey instanceof RSAKey, "Signing key should be RSAKey");
        assertEquals(rsaKey.toRSAPublicKey(), ((RSAKey) signingKey).toRSAPublicKey(), "Public key should match");
    }

    @Test
    void testSignAndVerifyCompleteFlow() throws Exception {
        // Arrange - Create a complete credential as per specification
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);
        
        UserInputEvidence evidence = UserInputEvidence.builder()
                .type("UserInputEvidence")
                .prompt("Buy something cheap on Nov 11 night")
                .timestamp(now)
                .channel("voice")
                .deviceFingerprint("dfp_abc123")
                .build();
        
        Proof proof = new Proof.Builder()
                .type("JwtProof2020")
                .created(now)
                .verificationMethod(TEST_ISSUER + "/#key-01")
                .build();
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(evidence)
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(proof)
                .build();

        // Act - Sign the credential
        String signedJwt = signer.sign(credential);

        // Assert - Verify the signature and content
        VerifiableCredential verifiedCredential = verifier.verify(signedJwt);
        
        // Verify all required claims are present and correct
        assertEquals(TEST_JTI, verifiedCredential.getJti(), "JTI should be preserved");
        assertEquals(TEST_ISSUER, verifiedCredential.getIss(), "Issuer should be preserved");
        assertEquals(TEST_SUBJECT, verifiedCredential.getSub(), "Subject should be preserved");
        assertEquals("VerifiableCredential", verifiedCredential.getType(), "Type should be VerifiableCredential");
        assertEquals(TEST_ISSUER, verifiedCredential.getIssuer(), "W3C issuer should be preserved");
        
        // Verify credential subject
        assertNotNull(verifiedCredential.getCredentialSubject(), "Credential subject should not be null");
        assertEquals("UserInputEvidence", verifiedCredential.getCredentialSubject().getType(), "Evidence type should match");
        assertEquals("Buy something cheap on Nov 11 night", verifiedCredential.getCredentialSubject().getPrompt(), "Prompt should be preserved");
        assertEquals("voice", verifiedCredential.getCredentialSubject().getChannel(), "Channel should be preserved");
        assertEquals("dfp_abc123", verifiedCredential.getCredentialSubject().getDeviceFingerprint(), "Device fingerprint should be preserved");
        
        // Verify proof
        assertNotNull(verifiedCredential.getProof(), "Proof should not be null");
        assertEquals("JwtProof2020", verifiedCredential.getProof().getType(), "Proof type should match");
    }

    @Test
    void testSignWithDifferentKeyId() throws Exception {
        // Arrange
        String differentKeyId = "key-02";
        RSAKeyGenerator differentKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey differentKey = differentKeyGenerator.keyID(differentKeyId).generate();
        DefaultVcSigner signerWithDifferentKey = new DefaultVcSigner(differentKey, differentKeyId, TEST_ISSUER);
        
        Instant now = Instant.now();
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(now.plusSeconds(3600))
                .type("VerifiableCredential")
                .credentialSubject(UserInputEvidence.builder()
                        .type("UserInputEvidence")
                        .prompt("Test prompt")
                        .timestamp(now)
                        .build())
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(now.plusSeconds(3600))
                .proof(new Proof.Builder()
                        .type("JwtProof2020")
                        .created(now)
                        .verificationMethod(TEST_ISSUER + "/#key-02")
                        .build())
                .build();

        // Act
        String signedJwt = signerWithDifferentKey.sign(credential);

        // Assert
        assertNotNull(signedJwt, "Signed JWT should not be null");
        
        // Verify with the correct key
        JwksProvider differentJwksProvider = new StaticJwksProvider(differentKey);
        DefaultVcVerifier verifierWithDifferentKey = new DefaultVcVerifier(differentJwksProvider);
        VerifiableCredential verifiedCredential = verifierWithDifferentKey.verify(signedJwt);
        assertNotNull(verifiedCredential, "Credential should be verifiable with the correct key");
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
                    // Return the key if it matches
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
