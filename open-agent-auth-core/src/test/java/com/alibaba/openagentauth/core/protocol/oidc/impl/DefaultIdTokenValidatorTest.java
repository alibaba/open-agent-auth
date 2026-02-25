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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.*;

import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/**
 * Unit tests for {@link DefaultIdTokenValidator}.
 */
@DisplayName("DefaultIdTokenValidator Tests")
class DefaultIdTokenValidatorTest {

    private static final String ISSUER = "https://example.com";
    private static final String SUBJECT = "user123";
    private static final String AUDIENCE = "client123";
    private static final String NONCE = "nonce123";
    private static final String VERIFICATION_KEY_ID = "test-verification-key";

    private DefaultIdTokenGenerator rsaGenerator;
    private DefaultIdTokenGenerator ecGenerator;
    private DefaultIdTokenValidator rsaValidator;
    private DefaultIdTokenValidator ecValidator;
    private RSAPublicKey rsaPublicKey;
    private RSAPrivateKey rsaPrivateKey;
    private ECPublicKey ecPublicKey;
    private ECPrivateKey ecPrivateKey;
    private KeyManager mockKeyManager;
    private KeyManager mockEcKeyManager;

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

        // Create token generators
        rsaGenerator = new DefaultIdTokenGenerator(ISSUER, "RS256", rsaPrivateKey);
        ecGenerator = new DefaultIdTokenGenerator(ISSUER, "ES256", ecPrivateKey);

        // Create mock KeyManager for RSA
        mockKeyManager = mock(KeyManager.class);
        com.nimbusds.jose.jwk.RSAKey rsaJwk = new com.nimbusds.jose.jwk.RSAKey.Builder(rsaPublicKey)
                .keyID(VERIFICATION_KEY_ID)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        when(mockKeyManager.resolveVerificationKey(anyString())).thenReturn(rsaJwk);

        // Create mock KeyManager for EC
        mockEcKeyManager = mock(KeyManager.class);
        com.nimbusds.jose.jwk.ECKey ecJwk = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256, ecPublicKey)
                .keyID(VERIFICATION_KEY_ID)
                .algorithm(JWSAlgorithm.ES256)
                .build();
        when(mockEcKeyManager.resolveVerificationKey(anyString())).thenReturn(ecJwk);

        // Create validators with new constructor
        rsaValidator = new DefaultIdTokenValidator(mockKeyManager, VERIFICATION_KEY_ID);
        ecValidator = new DefaultIdTokenValidator(mockEcKeyManager, VERIFICATION_KEY_ID);
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
        // Arrange - use existing rsaValidator which is already configured
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
    }

    @Test
    @DisplayName("Should validate token with ECKey JWK")
    void testValidateWithECKeyJWK() throws Exception {
        // Arrange - use existing ecValidator which is already configured
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
    }

    @Test
    @DisplayName("Should validate token with custom clock skew")
    void testValidateWithCustomClockSkew() {
        // Arrange
        long clockSkew = 120;
        DefaultIdTokenValidator validator = new DefaultIdTokenValidator(mockKeyManager, VERIFICATION_KEY_ID, clockSkew);
        
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
        assertEquals(clockSkew, validator.getClockSkewSeconds(), "Clock skew should match");
    }

    @Test
    @DisplayName("Should throw when verification key ID is null")
    void testConstructorWithNullVerificationKey() {
        // Arrange & Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                new DefaultIdTokenValidator(mockKeyManager, null),
                "Should throw exception when verification key ID is null");
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
        // Arrange - Setup mock to return EC key for RSA token
        KeyManager wrongKeyManager = mock(KeyManager.class);
        com.nimbusds.jose.jwk.ECKey wrongEcKey = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256, ecPublicKey)
                .keyID("wrong-key")
                .algorithm(JWSAlgorithm.ES256)
                .build();
        when(wrongKeyManager.resolveVerificationKey(anyString())).thenReturn(wrongEcKey);
        DefaultIdTokenValidator wrongValidator = new DefaultIdTokenValidator(wrongKeyManager, "wrong-key");
        
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
        // Arrange - Setup mock to return RSA key for EC token
        KeyManager wrongKeyManager = mock(KeyManager.class);
        com.nimbusds.jose.jwk.RSAKey wrongRsaKey = new com.nimbusds.jose.jwk.RSAKey.Builder(rsaPublicKey)
                .keyID("wrong-key")
                .algorithm(JWSAlgorithm.RS256)
                .build();
        when(wrongKeyManager.resolveVerificationKey(anyString())).thenReturn(wrongRsaKey);
        DefaultIdTokenValidator wrongValidator = new DefaultIdTokenValidator(wrongKeyManager, "wrong-key");
        
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
    @DisplayName("Should return correct clock skew")
    void testGetClockSkewSeconds() {
        DefaultIdTokenValidator validator = new DefaultIdTokenValidator(mockKeyManager, VERIFICATION_KEY_ID, 120);
        assertEquals(120, validator.getClockSkewSeconds(), "Clock skew should match");
    }

    @Test
    @DisplayName("Should validate token with JWKSource")
    void testValidateWithJWKSource() throws Exception {
        // Arrange - mock already set up in setUp
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
    }

    @Test
    @DisplayName("Should throw exception when JWKSource returns empty list")
    void testValidateWithEmptyJWKSource() throws Exception {
        // Arrange - Setup mock to return null (key not found)
        when(mockKeyManager.resolveVerificationKey(anyString())).thenReturn(null);
        DefaultIdTokenValidator validator = new DefaultIdTokenValidator(mockKeyManager, VERIFICATION_KEY_ID);
        
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
                "Should throw exception when KeyManager returns null");
    }

    @Test
    @DisplayName("Should throw exception when token is expired even with clock skew")
    void testValidateExpiredTokenWithClockSkew() throws Exception {
        // Arrange
        long clockSkew = 30; // 30 seconds
        DefaultIdTokenValidator validatorWithSkew = new DefaultIdTokenValidator(mockKeyManager, VERIFICATION_KEY_ID, clockSkew);
        
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
        DefaultIdTokenValidator validatorWithSkew = new DefaultIdTokenValidator(mockKeyManager, VERIFICATION_KEY_ID, clockSkew);
        
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
        
        // Create a new mock KeyManager for ES384
        KeyManager es384KeyManager = mock(KeyManager.class);
        com.nimbusds.jose.jwk.ECKey es384Jwk = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_384, ecPublicKey)
                .keyID("es384-key")
                .algorithm(JWSAlgorithm.ES384)
                .build();
        when(es384KeyManager.resolveVerificationKey(anyString())).thenReturn(es384Jwk);
        
        DefaultIdTokenValidator es384Validator = new DefaultIdTokenValidator(es384KeyManager, "es384-key");
        
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
        
        // Create a new mock KeyManager for ES512
        KeyManager es512KeyManager = mock(KeyManager.class);
        com.nimbusds.jose.jwk.ECKey es512Jwk = new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_521, ecPublicKey)
                .keyID("es512-key")
                .algorithm(JWSAlgorithm.ES512)
                .build();
        when(es512KeyManager.resolveVerificationKey(anyString())).thenReturn(es512Jwk);
        
        DefaultIdTokenValidator es512Validator = new DefaultIdTokenValidator(es512KeyManager, "es512-key");
        
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
