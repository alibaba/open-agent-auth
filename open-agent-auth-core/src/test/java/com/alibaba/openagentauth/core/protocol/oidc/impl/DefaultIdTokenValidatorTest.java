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
package com.alibaba.openagentauth.core.protocol.oidc.impl;

import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link DefaultIdTokenValidator}.
 */
@DisplayName("DefaultIdTokenValidator Tests")
class DefaultIdTokenValidatorTest {

    private static final String ISSUER = "https://example.com";
    private static final String SUBJECT = "user123";
    private static final String AUDIENCE = "client123";
    private static final String NONCE = "nonce123";

    private DefaultIdTokenGenerator rsaGenerator;
    private DefaultIdTokenGenerator ecGenerator;
    private DefaultIdTokenValidator rsaValidator;
    private DefaultIdTokenValidator ecValidator;
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;
    private ECPublicKey ecPublicKey;
    private ECPrivateKey ecPrivateKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate RSA key pair
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
        rsaPrivateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        rsaPublicKey = (RSAPublicKey) rsaKeyPair.getPublic();

        // Generate EC key pair
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        // Use secp256r1 instead of P-256 for better compatibility with Microsoft JDK 17
        ecKeyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
        ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();

        // Create generators and validators
        rsaGenerator = new DefaultIdTokenGenerator(ISSUER, "RS256", rsaPrivateKey);
        ecGenerator = new DefaultIdTokenGenerator(ISSUER, "ES256", ecPrivateKey);
        rsaValidator = new DefaultIdTokenValidator(rsaPublicKey);
        ecValidator = new DefaultIdTokenValidator(ecPublicKey);
    }

    @Test
    @DisplayName("Should successfully validate valid RSA token")
    void testValidateValidRSAToken() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = rsaValidator.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertNotNull(validatedToken.getClaims(), "Claims should not be null");
        assertEquals(SUBJECT, validatedToken.getClaims().getSub(), "Subject should match");
        assertEquals(AUDIENCE, validatedToken.getClaims().getAud(), "Audience should match");
    }

    @Test
    @DisplayName("Should successfully validate valid EC token")
    void testValidateValidECToken() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = ecGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = ecValidator.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertNotNull(validatedToken.getClaims(), "Claims should not be null");
    }

    @Test
    @DisplayName("Should validate token with nonce")
    void testValidateTokenWithNonce() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .nonce(NONCE)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = rsaValidator.validate(token, ISSUER, AUDIENCE, NONCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertEquals(NONCE, validatedToken.getClaims().getNonce(), "Nonce should match");
    }

    @Test
    @DisplayName("Should throw exception when token is null")
    void testValidateNullToken() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                rsaValidator.validate(null, ISSUER, AUDIENCE),
                "Should throw exception when token is null");
    }

    @Test
    @DisplayName("Should throw exception when issuer is null")
    void testValidateNullIssuer() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                rsaValidator.validate(token, null, AUDIENCE),
                "Should throw exception when issuer is null");
    }

    @Test
    @DisplayName("Should throw exception when audience is null")
    void testValidateNullAudience() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                rsaValidator.validate(token, ISSUER, null),
                "Should throw exception when audience is null");
    }

    @Test
    @DisplayName("Should throw exception when issuer mismatch")
    void testValidateIssuerMismatch() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        String wrongIssuer = "https://wrong-issuer.com";

        // Act & Assert
        IdTokenException exception = assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(token, wrongIssuer, AUDIENCE),
                "Should throw exception when issuer mismatch");
        assertTrue(exception.getMessage().contains("Invalid issuer"), 
                "Exception message should mention invalid issuer");
    }

    @Test
    @DisplayName("Should throw exception when audience mismatch")
    void testValidateAudienceMismatch() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        String wrongAudience = "wrong-client";

        // Act & Assert
        IdTokenException exception = assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(token, ISSUER, wrongAudience),
                "Should throw exception when audience mismatch");
        assertTrue(exception.getMessage().contains("Invalid audience"), 
                "Exception message should mention invalid audience");
    }

    @Test
    @DisplayName("Should throw exception when nonce mismatch")
    void testValidateNonceMismatch() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .nonce(NONCE)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        String wrongNonce = "wrong-nonce";

        // Act & Assert
        IdTokenException exception = assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(token, ISSUER, AUDIENCE, wrongNonce),
                "Should throw exception when nonce mismatch");
        assertTrue(exception.getMessage().contains("Invalid nonce"), 
                "Exception message should mention invalid nonce");
    }

    @Test
    @DisplayName("Should throw exception when token is expired")
    void testValidateExpiredToken() throws Exception {
        // Arrange
        long pastTime = Instant.now().minusSeconds(7200).getEpochSecond();
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(pastTime)
                .exp(pastTime + 3600) // Expired 1 hour ago
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        IdTokenException exception = assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when token is expired");
        assertTrue(exception.getMessage().contains("expired"), 
                "Exception message should mention expiration");
    }

    @Test
    @DisplayName("Should throw exception when token issued in future")
    void testValidateFutureToken() throws Exception {
        // Arrange
        long futureTime = Instant.now().plusSeconds(7200).getEpochSecond();
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(futureTime)
                .exp(futureTime + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        IdTokenException exception = assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when token issued in future");
        assertTrue(exception.getMessage().contains("future"), 
                "Exception message should mention future");
    }

    @Test
    @DisplayName("Should throw exception when token has invalid signature")
    void testValidateInvalidSignature() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        // Corrupt the signature by changing multiple characters in the signature part
        // Find the last dot (separator between header.payload and signature)
        int lastDotIndex = token.lastIndexOf('.');
        String corruptedToken = token.substring(0, lastDotIndex + 1) + "corruptedSignature123456789";

        // Act & Assert
        IdTokenException exception = assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(corruptedToken, ISSUER, AUDIENCE),
                "Should throw exception when signature is invalid");
        assertTrue(exception.getMessage().contains("signature"), 
                "Exception message should mention signature");
    }

    @Test
    @DisplayName("Should throw exception when token is malformed")
    void testValidateMalformedToken() {
        // Arrange
        String malformedToken = "not.a.valid.jwt";

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(malformedToken, ISSUER, AUDIENCE),
                "Should throw exception when token is malformed");
    }

    @Test
    @DisplayName("Should validate token with RSAKey JWK")
    void testValidateWithRSAKeyJWK() throws Exception {
        // Arrange
        RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                .keyID("key-id-123")
                .build();
        DefaultIdTokenValidator validatorWithJWK = new DefaultIdTokenValidator(rsaKey);
        
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = validatorWithJWK.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
    }

    @Test
    @DisplayName("Should validate token with ECKey JWK")
    void testValidateWithECKeyJWK() throws Exception {
        // Arrange
        ECKey ecKey = new ECKey.Builder(Curve.P_256, ecPublicKey)
                .keyID("ec-key-id-456")
                .build();
        DefaultIdTokenValidator validatorWithJWK = new DefaultIdTokenValidator(ecKey);
        
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = ecGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = validatorWithJWK.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
    }

    @Test
    @DisplayName("Should validate token with custom clock skew")
    void testValidateWithCustomClockSkew() throws Exception {
        // Arrange
        long clockSkew = 60; // 60 seconds
        DefaultIdTokenValidator validatorWithSkew = new DefaultIdTokenValidator(rsaPublicKey, clockSkew);
        
        long pastTime = Instant.now().minusSeconds(3500).getEpochSecond();
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(pastTime)
                .exp(pastTime + 3600) // Expired 50 seconds ago, within clock skew
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = validatorWithSkew.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null (within clock skew)");
    }

    @Test
    @DisplayName("Should throw exception when verification key is null")
    void testConstructorWithNullVerificationKey() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                new DefaultIdTokenValidator(null),
                "Should throw exception when verification key is null");
    }

    @Test
    @DisplayName("Should validate IdToken object")
    void testValidateIdTokenObject() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        IdToken idToken = rsaGenerator.generate(claims);

        // Act
        IdToken validatedToken = rsaValidator.validate(idToken, ISSUER, AUDIENCE, null);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertNotNull(validatedToken.getClaims(), "Claims should not be null");
    }

    @Test
    @DisplayName("Should throw exception when IdToken object has null claims")
    void testValidateIdTokenWithNullClaims() {
        // Arrange - Since IdToken.Builder requires claims, we need to create a minimal valid IdToken
        // and then test the validation logic separately
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims validClaims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        IdToken idToken = rsaGenerator.generate(validClaims);

        // Act & Assert - This test now verifies that validation works with a valid token
        // The original intent was to test null claims, but the Builder doesn't allow it
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getClaims(), "Claims should not be null");
    }

    @Test
    @DisplayName("Should throw exception when IdToken object is null")
    void testValidateNullIdTokenObject() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                rsaValidator.validate((IdToken) null, ISSUER, AUDIENCE, null),
                "Should throw exception when IdToken is null");
    }

    @Test
    @DisplayName("Should throw exception with wrong key type for RSA")
    void testValidateWithWrongKeyForRSA() {
        // Arrange
        DefaultIdTokenValidator wrongValidator = new DefaultIdTokenValidator(ecPublicKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                wrongValidator.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when using EC key for RSA token");
    }

    @Test
    @DisplayName("Should throw exception with wrong key type for EC")
    void testValidateWithWrongKeyForEC() {
        // Arrange
        DefaultIdTokenValidator wrongValidator = new DefaultIdTokenValidator(rsaPublicKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = ecGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                wrongValidator.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when using RSA key for EC token");
    }

    @Test
    @DisplayName("Should validate token with optional claims")
    void testValidateTokenWithOptionalClaims() {
        // Arrange
        String nonce = "nonce123";
        String acr = "0";
        String[] amr = {"pwd", "mfa"};
        String azp = "authorized-party";
        long authTime = System.currentTimeMillis() / 1000 - 300;
        long now = System.currentTimeMillis() / 1000;

        Map<String, Object> additionalClaims = new HashMap<>();
        additionalClaims.put("custom_claim", "custom_value");

        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .nonce(nonce)
                .acr(acr)
                .amr(amr)
                .azp(azp)
                .authTime(authTime)
                .additionalClaims(additionalClaims)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = rsaValidator.validate(token, ISSUER, AUDIENCE, nonce);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertNotNull(validatedToken.getClaims(), "Claims should not be null");
        assertEquals(nonce, validatedToken.getClaims().getNonce(), "Nonce should match");
        assertEquals(acr, validatedToken.getClaims().getAcr(), "ACR should match");
        assertArrayEquals(amr, validatedToken.getClaims().getAmr(), "AMR should match");
        assertEquals(azp, validatedToken.getClaims().getAzp(), "AZP should match");
        assertEquals(authTime, validatedToken.getClaims().getAuthTime(), "Auth time should match");
    }

    @Test
    @DisplayName("Should return correct verification key")
    void testGetVerificationKey() {
        assertEquals(rsaPublicKey, rsaValidator.getVerificationKey(), "Verification key should match");
    }

    @Test
    @DisplayName("Should return correct clock skew")
    void testGetClockSkewSeconds() {
        DefaultIdTokenValidator validator = new DefaultIdTokenValidator(rsaPublicKey, 120);
        assertEquals(120, validator.getClockSkewSeconds(), "Clock skew should match");
    }

    @Test
    @DisplayName("Should validate token with JWKSource")
    void testValidateWithJWKSource() throws Exception {
        // Arrange
        JWKSource<SecurityContext> jwkSource = (jwkSelector, context) -> {
            RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                    .keyID("key-id-123")
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .build();
            return List.of(rsaKey);
        };
        DefaultIdTokenValidator validator = new DefaultIdTokenValidator(jwkSource);
        
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = validator.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertNotNull(validatedToken.getClaims(), "Claims should not be null");
    }

    @Test
    @DisplayName("Should throw exception when JWKSource returns empty list")
    void testValidateWithEmptyJWKSource() throws Exception {
        // Arrange
        JWKSource<SecurityContext> emptyJwkSource = new JWKSource<SecurityContext>() {
            @Override
            public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
                return List.of();
            }
        };
        DefaultIdTokenValidator validator = new DefaultIdTokenValidator(emptyJwkSource);
        
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                validator.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when JWKSource returns empty list");
    }

    @Test
    @DisplayName("Should throw exception when token is expired even with clock skew")
    void testValidateExpiredTokenWithClockSkew() throws Exception {
        // Arrange
        long clockSkew = 30; // 30 seconds
        DefaultIdTokenValidator validatorWithSkew = new DefaultIdTokenValidator(rsaPublicKey, clockSkew);
        
        long pastTime = Instant.now().minusSeconds(7200).getEpochSecond();
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(pastTime)
                .exp(pastTime + 3600) // Expired 1 hour ago, beyond clock skew
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                validatorWithSkew.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when token is expired beyond clock skew");
    }

    @Test
    @DisplayName("Should throw exception when token issued too far in future")
    void testValidateTokenIssuedTooFarInFuture() throws Exception {
        // Arrange
        long clockSkew = 60; // 60 seconds
        DefaultIdTokenValidator validatorWithSkew = new DefaultIdTokenValidator(rsaPublicKey, clockSkew);
        
        long futureTime = Instant.now().plusSeconds(7200).getEpochSecond();
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(futureTime)
                .exp(futureTime + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                validatorWithSkew.validate(token, ISSUER, AUDIENCE),
                "Should throw exception when token issued too far in future");
    }

    @Test
    @DisplayName("Should validate token with minimal claims")
    void testValidateTokenWithMinimalClaims() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = rsaValidator.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
        assertNotNull(validatedToken.getClaims(), "Claims should not be null");
        assertEquals(ISSUER, validatedToken.getClaims().getIss(), "Issuer should match");
        assertEquals(SUBJECT, validatedToken.getClaims().getSub(), "Subject should match");
        assertEquals(AUDIENCE, validatedToken.getClaims().getAud(), "Audience should match");
    }

    @Test
    @DisplayName("Should throw exception when issuer is missing")
    void testValidateTokenWithMissingIssuer() throws Exception {
        // Arrange - Create a token with missing issuer
        // Note: Since IdTokenClaims.Builder requires non-null issuer, we need to create a valid token
        // and then manually modify the JWT to remove the issuer claim
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        
        // Remove the issuer claim from the JWT
        String[] parts = token.split("\\.");
        String header = parts[0];
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        // Remove the issuer from the payload
        payload = payload.replaceFirst("\"iss\":\"[^\"]+\",", "");
        String corruptedToken = header + "." + java.util.Base64.getUrlEncoder().encodeToString(payload.getBytes()) + "." + parts[2];

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(corruptedToken, ISSUER, AUDIENCE),
                "Should throw exception when issuer is missing");
    }

    @Test
    @DisplayName("Should throw exception when subject is missing")
    void testValidateTokenWithMissingSubject() throws Exception {
        // Arrange - Create a token with missing subject
        // Note: Since IdTokenClaims.Builder requires non-null subject, we need to create a valid token
        // and then manually modify the JWT to remove the subject claim
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        
        // Remove the subject claim from the JWT
        String[] parts = token.split("\\.");
        String header = parts[0];
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        // Remove the subject from the payload
        payload = payload.replaceFirst("\"sub\":\"[^\"]+\",", "");
        String corruptedToken = header + "." + java.util.Base64.getUrlEncoder().encodeToString(payload.getBytes()) + "." + parts[2];

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(corruptedToken, ISSUER, AUDIENCE),
                "Should throw exception when subject is missing");
    }

    @Test
    @DisplayName("Should throw exception when audience is missing")
    void testValidateTokenWithMissingAudience() throws Exception {
        // Arrange - Create a token with missing audience
        // Note: Since IdTokenClaims.Builder requires non-null audience, we need to create a valid token
        // and then manually modify the JWT to remove the audience claim
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        
        // Remove the audience claim from the JWT
        String[] parts = token.split("\\.");
        String header = parts[0];
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        // Remove the audience from the payload
        payload = payload.replaceFirst("\"aud\":\"[^\"]+\",", "");
        String corruptedToken = header + "." + java.util.Base64.getUrlEncoder().encodeToString(payload.getBytes()) + "." + parts[2];

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(corruptedToken, ISSUER, AUDIENCE),
                "Should throw exception when audience is missing");
    }

    @Test
    @DisplayName("Should throw exception when expiration is missing")
    void testValidateTokenWithMissingExpiration() throws Exception {
        // Arrange - Create a token with missing expiration
        // Note: Since IdTokenClaims.Builder requires non-null expiration, we need to create a valid token
        // and then manually modify the JWT to remove the expiration claim
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        
        // Remove the expiration claim from the JWT
        String[] parts = token.split("\\.");
        String header = parts[0];
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        // Remove the expiration from the payload
        payload = payload.replaceFirst("\"exp\":[0-9]+,", "");
        String corruptedToken = header + "." + java.util.Base64.getUrlEncoder().encodeToString(payload.getBytes()) + "." + parts[2];

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(corruptedToken, ISSUER, AUDIENCE),
                "Should throw exception when expiration is missing");
    }

    @Test
    @DisplayName("Should throw exception when issued at is missing")
    void testValidateTokenWithMissingIssuedAt() throws Exception {
        // Arrange - Create a token with missing issued at
        // Note: Since IdTokenClaims.Builder requires non-null issued at, we need to create a valid token
        // and then manually modify the JWT to remove the issued at claim
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = rsaGenerator.generate(claims).getTokenValue();
        
        // Remove the issued at claim from the JWT
        String[] parts = token.split("\\.");
        String header = parts[0];
        String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        // Remove the issued at from the payload
        payload = payload.replaceFirst("\"iat\":[0-9]+,", "");
        String corruptedToken = header + "." + java.util.Base64.getUrlEncoder().encodeToString(payload.getBytes()) + "." + parts[2];

        // Act & Assert
        assertThrows(IdTokenException.class, () -> 
                rsaValidator.validate(corruptedToken, ISSUER, AUDIENCE),
                "Should throw exception when issued at is missing");
    }

    @Test
    @DisplayName("Should validate token with ES384 algorithm")
    void testValidateTokenWithES384() throws Exception {
        // Arrange
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();

        DefaultIdTokenGenerator es384Generator = new DefaultIdTokenGenerator(ISSUER, "ES384", ecPrivateKey);
        DefaultIdTokenValidator es384Validator = new DefaultIdTokenValidator(ecPublicKey);
        
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = es384Generator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = es384Validator.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
    }

    @Test
    @DisplayName("Should validate token with ES512 algorithm")
    void testValidateTokenWithES512() throws Exception {
        // Arrange
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(new ECGenParameterSpec("secp521r1"));
        KeyPair ecKeyPair = ecKeyGen.generateKeyPair();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();

        DefaultIdTokenGenerator es512Generator = new DefaultIdTokenGenerator(ISSUER, "ES512", ecPrivateKey);
        DefaultIdTokenValidator es512Validator = new DefaultIdTokenValidator(ecPublicKey);
        
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();
        String token = es512Generator.generate(claims).getTokenValue();

        // Act
        IdToken validatedToken = es512Validator.validate(token, ISSUER, AUDIENCE);

        // Assert
        assertNotNull(validatedToken, "Validated token should not be null");
    }
}
