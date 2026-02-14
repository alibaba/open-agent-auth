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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link JwtVcEncoder}.
 * <p>
 * These tests validate the encoding functionality according to the
 * draft-liu-agent-operation-authorization-01 specification requirements:
 * </p>
 * <ul>
 *   <li>Proper mapping of VC fields to JWT claims</li>
 *   <li>Correct encoding of standard JWT claims (jti, iss, sub, iat, exp)</li>
 *   <li>Correct encoding of W3C VC custom claims (type, credentialSubject, issuer, etc.)</li>
 *   <li>RS256 algorithm usage for signing</li>
 *   <li>Key ID inclusion in JWT header</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization-01/">draft-liu-agent-operation-authorization-01</a>
 */
class JwtVcEncoderTest {

    private static final String TEST_ISSUER = "https://client.myassistant.example";
    private static final String TEST_KEY_ID = "key-01";
    private static final String TEST_JTI = "pt-001";
    private static final String TEST_SUBJECT = "user_12345";

    @Test
    void testEncodeUnsignedJwt() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);

        // Act
        String unsignedJwt = JwtVcEncoder.encode(credential);

        // Assert
        assertNotNull(unsignedJwt, "Unsigned JWT should not be null");
        assertFalse(unsignedJwt.isEmpty(), "Unsigned JWT should not be empty");
        
        // Verify JWT structure - unsigned JWT has format: header.payload.
        // The signature part is empty, so split by "." will give us 3 parts with last part empty
        String[] parts = unsignedJwt.split("\\.", -1); // -1 to keep trailing empty strings
        assertEquals(3, parts.length, "JWT should have three parts (header.payload.empty)");
        assertTrue(parts[0].length() > 0, "Header should not be empty");
        assertTrue(parts[1].length() > 0, "Payload should not be empty");
        assertTrue(parts[2].isEmpty(), "Signature should be empty for unsigned JWT");

        // Note: Cannot use SignedJWT.parse() for unsigned JWT as it requires non-empty signature
        // Use encodeAndSign() for full JWT parsing tests
    }

    @Test
    void testEncodeAndSignJwt() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);

        // Assert
        assertNotNull(signedJwt, "Signed JWT should not be null");
        assertFalse(signedJwt.isEmpty(), "Signed JWT should not be empty");
        
        // Verify JWT structure
        String[] parts = signedJwt.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify the JWT can be parsed
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        assertEquals("RS256", parsedJwt.getHeader().getAlgorithm().getName(), "Algorithm should be RS256");
        assertEquals(TEST_KEY_ID, parsedJwt.getHeader().getKeyID(), "Key ID should match");
        
        // Verify claims
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();
        assertEquals(TEST_JTI, claimsSet.getJWTID(), "JTI should match");
        assertEquals(TEST_ISSUER, claimsSet.getIssuer(), "Issuer should match");
        assertEquals(TEST_SUBJECT, claimsSet.getSubject(), "Subject should match");
        assertEquals("VerifiableCredential", claimsSet.getClaim("type"), "Type should match");
    }

    @Test
    void testEncodeWithNullCredential() {
        // Act & Assert
        assertThrows(
                NullPointerException.class,
                () -> JwtVcEncoder.encode(null),
                "Should throw NullPointerException for null credential"
        );
    }

    @Test
    void testEncodeAndSignWithNullCredential() throws Exception {
        // Arrange
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act & Assert
        assertThrows(
                NullPointerException.class,
                () -> JwtVcEncoder.encodeAndSign(null, signingKey, TEST_KEY_ID),
                "Should throw NullPointerException for null credential"
        );
    }

    @Test
    void testEncodeAndSignWithNullSigningKey() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        VerifiableCredential credential = createTestCredential(now, expiration);

        // Act & Assert
        assertThrows(
                NullPointerException.class,
                () -> JwtVcEncoder.encodeAndSign(credential, null, TEST_KEY_ID),
                "Should throw NullPointerException for null signing key"
        );
    }

    @Test
    void testEncodeAndSignWithNullKeyId() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        VerifiableCredential credential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act & Assert
        assertThrows(
                NullPointerException.class,
                () -> JwtVcEncoder.encodeAndSign(credential, signingKey, null),
                "Should throw NullPointerException for null key ID"
        );
    }

    @Test
    void testEncodeWithAllRequiredClaims() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);

        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act - Use signed JWT for parsing tests
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();

        // Assert - Verify all standard JWT claims
        assertEquals(TEST_JTI, claimsSet.getJWTID(), "JTI should be present");
        assertEquals(TEST_ISSUER, claimsSet.getIssuer(), "Issuer should be present");
        assertEquals(TEST_SUBJECT, claimsSet.getSubject(), "Subject should be present");
        assertNotNull(claimsSet.getIssueTime(), "Issue time should be present");
        assertNotNull(claimsSet.getExpirationTime(), "Expiration time should be present");
        
        // Assert - Verify all W3C VC custom claims
        assertEquals("VerifiableCredential", claimsSet.getClaim("type"), "Type should be present");
        assertNotNull(claimsSet.getClaim("credentialSubject"), "Credential subject should be present");
        assertEquals(TEST_ISSUER, claimsSet.getClaim("issuer"), "W3C VC issuer should be present");
        assertNotNull(claimsSet.getClaim("issuanceDate"), "Issuance date should be present");
        assertNotNull(claimsSet.getClaim("expirationDate"), "Expiration date should be present");
        assertNotNull(claimsSet.getClaim("proof"), "Proof should be present");
    }

    @Test
    void testEncodeWithOptionalClaims() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        // Create credential with minimal required claims
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
                .proof(createTestProof(now))
                .build();

        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act - Use signed JWT for parsing tests
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();

        // Assert
        assertEquals(TEST_JTI, claimsSet.getJWTID(), "JTI should match");
        assertEquals(TEST_ISSUER, claimsSet.getIssuer(), "Issuer should match");
        assertEquals(TEST_SUBJECT, claimsSet.getSubject(), "Subject should match");
    }

    @Test
    void testEncodeWithCredentialSubject() throws Exception {
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

        // Act - Use signed JWT for parsing tests
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();

        // Assert - JWT library returns Map for custom claims
        Object credentialSubject = claimsSet.getClaim("credentialSubject");
        assertNotNull(credentialSubject, "Credential subject should be present");
        assertTrue(credentialSubject instanceof java.util.Map, "Credential subject should be Map (JWT library default)");

        // Verify the Map contains expected values
        java.util.Map<?, ?> subjectMap = (java.util.Map<?, ?>) credentialSubject;
        assertEquals("UserInputEvidence", subjectMap.get("type"), "Evidence type should match");
        assertEquals("Buy something cheap on Nov 11 night", subjectMap.get("prompt"), "Prompt should match");
        assertEquals("voice", subjectMap.get("channel"), "Channel should match");
        assertEquals("dfp_abc123", subjectMap.get("deviceFingerprint"), "Device fingerprint should match");
    }

    @Test
    void testEncodeWithProof() throws Exception {
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

        // Act - Use signed JWT for parsing tests
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();

        // Assert - JWT library returns Map for custom claims
        Object proofClaim = claimsSet.getClaim("proof");
        assertNotNull(proofClaim, "Proof should be present");
        assertTrue(proofClaim instanceof java.util.Map, "Proof should be Map (JWT library default)");

        // Verify the Map contains expected values
        java.util.Map<?, ?> proofMap = (java.util.Map<?, ?>) proofClaim;
        assertEquals("JwtProof2020", proofMap.get("type"), "Proof type should match");
        assertEquals(TEST_ISSUER + "/#key-01", proofMap.get("verificationMethod"), "Verification method should match");
    }

    @Test
    void testEncodeWithIso8601Dates() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);

        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act - Use signed JWT for parsing tests
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();

        // Assert - Verify ISO 8601 format for W3C VC dates
        Object issuanceDate = claimsSet.getClaim("issuanceDate");
        Object expirationDate = claimsSet.getClaim("expirationDate");
        
        assertNotNull(issuanceDate, "Issuance date should be present");
        assertNotNull(expirationDate, "Expiration date should be present");
        
        assertTrue(issuanceDate.toString().contains("T"), "Issuance date should be in ISO 8601 format");
        assertTrue(expirationDate.toString().contains("T"), "Expiration date should be in ISO 8601 format");
    }

    @Test
    void testEncodeWithNullOptionalClaims() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        // Create credential with null optional claims
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

        // Act - Use signed JWT for parsing tests
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_KEY_ID);
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();

        // Assert - Null claims should not be included
        assertNull(claimsSet.getClaim("proof"), "Null proof should not be included");
    }

    @Test
    void testEncodeRoundTrip() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey signingKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();

        // Act - Encode and sign
        String signedJwt = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_KEY_ID);
        
        // Decode using JwtVcDecoder
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(signedJwt);

        // Assert - Verify round-trip preserves all fields
        assertEquals(originalCredential.getJti(), decodedCredential.getJti(), "JTI should match");
        assertEquals(originalCredential.getIss(), decodedCredential.getIss(), "Issuer should match");
        assertEquals(originalCredential.getSub(), decodedCredential.getSub(), "Subject should match");
        assertEquals(originalCredential.getIat(), decodedCredential.getIat(), "Issued at should match");
        assertEquals(originalCredential.getExp(), decodedCredential.getExp(), "Expiration should match");
        assertEquals(originalCredential.getType(), decodedCredential.getType(), "Type should match");
        assertEquals(originalCredential.getIssuer(), decodedCredential.getIssuer(), "W3C VC issuer should match");
        assertEquals(originalCredential.getIssuanceDate(), decodedCredential.getIssuanceDate(), "Issuance date should match");
        assertEquals(originalCredential.getExpirationDate(), decodedCredential.getExpirationDate(), "Expiration date should match");
        
        // Verify credential subject
        assertNotNull(decodedCredential.getCredentialSubject(), "Credential subject should not be null");
        assertEquals(originalCredential.getCredentialSubject().getType(), decodedCredential.getCredentialSubject().getType(), "Evidence type should match");
        assertEquals(originalCredential.getCredentialSubject().getPrompt(), decodedCredential.getCredentialSubject().getPrompt(), "Prompt should match");
        
        // Verify proof
        assertNotNull(decodedCredential.getProof(), "Proof should not be null");
        assertEquals(originalCredential.getProof().getType(), decodedCredential.getProof().getType(), "Proof type should match");
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
     * ECDSA algorithm tests
     */
    private static final String TEST_EC_KEY_ID = "ec-key-01";

    @Test
    void testEncodeAndSignWithES256() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256);
        ECKey signingKey = ecKeyGenerator.keyID(TEST_EC_KEY_ID).algorithm(com.nimbusds.jose.JWSAlgorithm.ES256).generate();

        // Act
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_EC_KEY_ID);

        // Assert
        assertNotNull(signedJwt, "Signed JWT should not be null");
        assertFalse(signedJwt.isEmpty(), "Signed JWT should not be empty");
        
        // Verify JWT structure
        String[] parts = signedJwt.split("\\.");
        assertEquals(3, parts.length, "JWT should have three parts");
        
        // Verify the JWT can be parsed
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        assertEquals("ES256", parsedJwt.getHeader().getAlgorithm().getName(), "Algorithm should be ES256");
        assertEquals(TEST_EC_KEY_ID, parsedJwt.getHeader().getKeyID(), "Key ID should match");
        
        // Verify claims
        JWTClaimsSet claimsSet = parsedJwt.getJWTClaimsSet();
        assertEquals(TEST_JTI, claimsSet.getJWTID(), "JTI should match");
        assertEquals(TEST_ISSUER, claimsSet.getIssuer(), "Issuer should match");
        assertEquals(TEST_SUBJECT, claimsSet.getSubject(), "Subject should match");
        assertEquals("VerifiableCredential", claimsSet.getClaim("type"), "Type should match");
    }

    @Test
    void testEncodeAndSignWithES384() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_384);
        ECKey signingKey = ecKeyGenerator.keyID(TEST_EC_KEY_ID).algorithm(com.nimbusds.jose.JWSAlgorithm.ES384).generate();

        // Act
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_EC_KEY_ID);

        // Assert
        assertNotNull(signedJwt, "Signed JWT should not be null");
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        assertEquals("ES384", parsedJwt.getHeader().getAlgorithm().getName(), "Algorithm should be ES384");
    }

    @Test
    void testEncodeAndSignWithES512() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_521);
        ECKey signingKey = ecKeyGenerator.keyID(TEST_EC_KEY_ID).algorithm(com.nimbusds.jose.JWSAlgorithm.ES512).generate();

        // Act
        String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, TEST_EC_KEY_ID);

        // Assert
        assertNotNull(signedJwt, "Signed JWT should not be null");
        SignedJWT parsedJwt = SignedJWT.parse(signedJwt);
        assertEquals("ES512", parsedJwt.getHeader().getAlgorithm().getName(), "Algorithm should be ES512");
    }

    @Test
    void testEncodeRoundTripWithES256() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential originalCredential = createTestCredential(now, expiration);
        
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256);
        ECKey signingKey = ecKeyGenerator.keyID(TEST_EC_KEY_ID).algorithm(com.nimbusds.jose.JWSAlgorithm.ES256).generate();

        // Act - Encode and sign with ES256
        String signedJwt = JwtVcEncoder.encodeAndSign(originalCredential, signingKey, TEST_EC_KEY_ID);
        
        // Decode using JwtVcDecoder
        VerifiableCredential decodedCredential = JwtVcDecoder.decode(signedJwt);

        // Assert - Verify round-trip preserves all fields
        assertEquals(originalCredential.getJti(), decodedCredential.getJti(), "JTI should match");
        assertEquals(originalCredential.getIss(), decodedCredential.getIss(), "Issuer should match");
        assertEquals(originalCredential.getSub(), decodedCredential.getSub(), "Subject should match");
        assertEquals(originalCredential.getType(), decodedCredential.getType(), "Type should match");
        assertEquals(originalCredential.getCredentialSubject().getType(), decodedCredential.getCredentialSubject().getType(), "Evidence type should match");
    }

    @Test
    void testEncodeWithECKeySignatureSize() throws Exception {
        // Arrange
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiration = now.plusSeconds(3600);
        
        VerifiableCredential credential = createTestCredential(now, expiration);
        
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey rsaKey = rsaKeyGenerator.keyID(TEST_KEY_ID).generate();
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256);
        ECKey ecKey = ecKeyGenerator.keyID(TEST_EC_KEY_ID).algorithm(com.nimbusds.jose.JWSAlgorithm.ES256).generate();

        // Act - Sign with both RSA and EC
        String rsaSignedJwt = JwtVcEncoder.encodeAndSign(credential, rsaKey, TEST_KEY_ID);
        String ecSignedJwt = JwtVcEncoder.encodeAndSign(credential, ecKey, TEST_EC_KEY_ID);

        // Assert - EC signature should be smaller than RSA signature
        String[] rsaParts = rsaSignedJwt.split("\\.");
        String[] ecParts = ecSignedJwt.split("\\.");
        
        assertTrue(ecParts[2].length() < rsaParts[2].length(), 
                "EC signature should be smaller than RSA signature");
        assertEquals(3, rsaParts.length, "RSA JWT should have three parts");
        assertEquals(3, ecParts.length, "EC JWT should have three parts");
    }
}
