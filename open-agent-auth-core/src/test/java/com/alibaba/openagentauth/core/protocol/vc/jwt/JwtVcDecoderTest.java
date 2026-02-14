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
package com.alibaba.openagentauth.core.protocol.vc.jwt;

import com.alibaba.openagentauth.core.model.evidence.Proof;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link JwtVcDecoder}.
 * <p>
 * These tests validate the decoding functionality according to the
 * draft-liu-agent-operation-authorization-01 specification requirements.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
class JwtVcDecoderTest {

    private static final String TEST_ISSUER = "https://client.myassistant.example";
    private static final String TEST_KEY_ID = "key-01";
    private static final String TEST_JTI = "pt-001";
    private static final String TEST_SUBJECT = "user_12345";

    @Test
    void testDecodeValidJwt() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNotNull(decodedCredential, "Decoded credential should not be null");
        assertEquals(TEST_JTI, decodedCredential.getJti(), "JTI should match");
        assertEquals(TEST_ISSUER, decodedCredential.getIss(), "Issuer should match");
        assertEquals(TEST_SUBJECT, decodedCredential.getSub(), "Subject should match");
        assertEquals("VerifiableCredential", decodedCredential.getType(), "Type should match");
    }

    @Test
    void testDecodeSignedJwt() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNotNull(decodedCredential, "Decoded credential should not be null");
        assertEquals(TEST_JTI, decodedCredential.getJti(), "JTI should match");
        assertEquals(TEST_ISSUER, decodedCredential.getIss(), "Issuer should match");
        assertEquals(TEST_SUBJECT, decodedCredential.getSub(), "Subject should match");
        assertEquals("VerifiableCredential", decodedCredential.getType(), "Type should match");
    }

    @Test
    void testDecodeWithNullJwt() {
        // Act & Assert
        assertThrows(
                NullPointerException.class,
                () -> JwtVcDecoder.decode(null),
                "Should throw NullPointerException for null JWT"
        );
    }

    @Test
    void testDecodeWithInvalidJwt() {
        // Arrange
        String invalidJwt = "invalid.jwt.string";

        // Act & Assert
        assertThrows(
                ParseException.class,
                () -> JwtVcDecoder.decode(invalidJwt),
                "Should throw ParseException for invalid JWT"
        );
    }

    @Test
    void testDecodeWithMalformedJwt() {
        // Arrange
        String malformedJwt = "header.payload"; // Missing signature

        // Act & Assert
        assertThrows(
                ParseException.class,
                () -> JwtVcDecoder.decode(malformedJwt),
                "Should throw ParseException for malformed JWT"
        );
    }

    @Test
    void testDecodeStandardJwtClaims() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert - Verify standard JWT claims
        assertEquals(TEST_JTI, decodedCredential.getJti(), "JTI should be decoded correctly");
        assertEquals(TEST_ISSUER, decodedCredential.getIss(), "Issuer should be decoded correctly");
        assertEquals(TEST_SUBJECT, decodedCredential.getSub(), "Subject should be decoded correctly");
        assertEquals(now.getEpochSecond(), decodedCredential.getIat(), "Issued at should be decoded correctly");
        assertEquals(expiration.getEpochSecond(), decodedCredential.getExp(), "Expiration should be decoded correctly");
    }

    @Test
    void testDecodeW3cVcClaims() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert - Verify W3C VC custom claims
        assertEquals("VerifiableCredential", decodedCredential.getType(), "Type should be decoded correctly");
        assertEquals(TEST_ISSUER, decodedCredential.getIssuer(), "W3C VC issuer should be decoded correctly");
        assertEquals(now.toString(), decodedCredential.getIssuanceDate(), "Issuance date should be decoded correctly");
        assertEquals(expiration.toString(), decodedCredential.getExpirationDate(), "Expiration date should be decoded correctly");
        
        // Verify credential subject
        assertNotNull(decodedCredential.getCredentialSubject(), "Credential subject should not be null");
        assertEquals("UserInputEvidence", decodedCredential.getCredentialSubject().getType(), "Evidence type should match");
        assertEquals("Buy something cheap on Nov 11 night", decodedCredential.getCredentialSubject().getPrompt(), "Prompt should match");
        
        // Verify proof
        assertNotNull(decodedCredential.getProof(), "Proof should not be null");
        assertEquals("JwtProof2020", decodedCredential.getProof().getType(), "Proof type should match");
    }

    @Test
    void testDecodeWithCredentialSubject() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        UserInputEvidence evidence = UserInputEvidence.builder()
                .type("UserInputEvidence")
                .prompt("Buy something cheap on Nov 11 night")
                .timestamp(now)
                .channel("voice")
                .deviceFingerprint("dfp_abc123")
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
                .proof(createTestProof(now))
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNotNull(decodedCredential.getCredentialSubject(), "Credential subject should not be null");
        UserInputEvidence decodedEvidence = decodedCredential.getCredentialSubject();
        assertEquals("UserInputEvidence", decodedEvidence.getType(), "Evidence type should match");
        assertEquals("Buy something cheap on Nov 11 night", decodedEvidence.getPrompt(), "Prompt should match");
        assertEquals("voice", decodedEvidence.getChannel(), "Channel should match");
        assertEquals("dfp_abc123", decodedEvidence.getDeviceFingerprint(), "Device fingerprint should match");
        assertEquals(now.toString(), decodedEvidence.getTimestamp(), "Timestamp should match");
    }

    @Test
    void testDecodeWithProof() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
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
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(proof)
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNotNull(decodedCredential.getProof(), "Proof should not be null");
        Proof decodedProof = decodedCredential.getProof();
        assertEquals("JwtProof2020", decodedProof.getType(), "Proof type should match");
        assertEquals(now.toString(), decodedProof.getCreated(), "Created timestamp should match");
        assertEquals(TEST_ISSUER + "/#key-01", decodedProof.getVerificationMethod(), "Verification method should match");
    }

    @Test
    void testDecodeWithMissingOptionalClaims() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        // Create credential with minimal claims
        VerifiableCredential credential = VerifiableCredential.builder()
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
                .proof(null) // Null proof
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert - Missing optional claims should be null
        assertNull(decodedCredential.getProof(), "Null proof should remain null");
    }

    @Test
    void testDecodeWithNullJti() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(null) // Null JTI
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
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNull(decodedCredential.getJti(), "Null JTI should remain null");
    }

    @Test
    void testDecodeWithNullIss() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(null) // Null issuer
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
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNull(decodedCredential.getIss(), "Null issuer should remain null");
    }

    @Test
    void testDecodeWithNullSub() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(null) // Null subject
                .iat(now)
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNull(decodedCredential.getSub(), "Null subject should remain null");
    }

    @Test
    void testDecodeWithNullIat() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        Long nullIat = null; // Use variable to avoid ambiguous method call

        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(nullIat) // Null issued at
                .exp(expiration)
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNull(decodedCredential.getIat(), "Null issued at should remain null");
    }

    @Test
    void testDecodeWithNullExp() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        Long nullExp = null; // Use variable to avoid ambiguous method call

        VerifiableCredential credential = VerifiableCredential.builder()
                .jti(TEST_JTI)
                .iss(TEST_ISSUER)
                .sub(TEST_SUBJECT)
                .iat(now)
                .exp(nullExp) // Null expiration
                .type("VerifiableCredential")
                .credentialSubject(createTestEvidence(now))
                .issuer(TEST_ISSUER)
                .issuanceDate(now)
                .expirationDate(expiration)
                .proof(createTestProof(now))
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNull(decodedCredential.getExp(), "Null expiration should remain null");
    }

    @Test
    void testDecodeEncodeRoundTrip() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert - Verify complete round-trip
        assertEquals(originalCredential.getJti(), decodedCredential.getJti(), "JTI should match after round-trip");
        assertEquals(originalCredential.getIss(), decodedCredential.getIss(), "Issuer should match after round-trip");
        assertEquals(originalCredential.getSub(), decodedCredential.getSub(), "Subject should match after round-trip");
        assertEquals(originalCredential.getIat(), decodedCredential.getIat(), "Issued at should match after round-trip");
        assertEquals(originalCredential.getExp(), decodedCredential.getExp(), "Expiration should match after round-trip");
        assertEquals(originalCredential.getType(), decodedCredential.getType(), "Type should match after round-trip");
        assertEquals(originalCredential.getIssuer(), decodedCredential.getIssuer(), "W3C VC issuer should match after round-trip");
        assertEquals(originalCredential.getIssuanceDate(), decodedCredential.getIssuanceDate(), "Issuance date should match after round-trip");
        assertEquals(originalCredential.getExpirationDate(), decodedCredential.getExpirationDate(), "Expiration date should match after round-trip");
        
        // Verify credential subject
        assertNotNull(decodedCredential.getCredentialSubject(), "Credential subject should not be null");
        assertEquals(originalCredential.getCredentialSubject().getType(), decodedCredential.getCredentialSubject().getType(), "Evidence type should match");
        assertEquals(originalCredential.getCredentialSubject().getPrompt(), decodedCredential.getCredentialSubject().getPrompt(), "Prompt should match");
        assertEquals(originalCredential.getCredentialSubject().getChannel(), decodedCredential.getCredentialSubject().getChannel(), "Channel should match");
        assertEquals(originalCredential.getCredentialSubject().getDeviceFingerprint(), decodedCredential.getCredentialSubject().getDeviceFingerprint(), "Device fingerprint should match");
        
        // Verify proof
        assertNotNull(decodedCredential.getProof(), "Proof should not be null");
        assertEquals(originalCredential.getProof().getType(), decodedCredential.getProof().getType(), "Proof type should match");
        assertEquals(originalCredential.getProof().getCreated(), decodedCredential.getProof().getCreated(), "Proof created should match");
        assertEquals(originalCredential.getProof().getVerificationMethod(), decodedCredential.getProof().getVerificationMethod(), "Verification method should match");
    }

    @Test
    void testDecodeWithDifferentCredentialSubjectTypes() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        // Create credential with different evidence type
        UserInputEvidence evidence = UserInputEvidence.builder()
                .type("CustomEvidenceType")
                .prompt("Custom prompt")
                .timestamp(now)
                .channel("mobile")
                .deviceFingerprint("custom-dfp")
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
                .proof(createTestProof(now))
                .build();
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        
        String jwtString = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Act
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(jwtString);

        // Assert
        assertNotNull(decodedCredential.getCredentialSubject(), "Credential subject should not be null");
        assertEquals("CustomEvidenceType", decodedCredential.getCredentialSubject().getType(), "Custom evidence type should be preserved");
        assertEquals("Custom prompt", decodedCredential.getCredentialSubject().getPrompt(), "Custom prompt should be preserved");
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
}
