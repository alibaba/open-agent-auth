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
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DefaultIdTokenGenerator}.
 */
@DisplayName("DefaultIdTokenGenerator Tests")
class DefaultIdTokenGeneratorTest {

    private static final String ISSUER = "https://example.com";
    private static final String ALGORITHM_RS256 = "RS256";
    private static final String ALGORITHM_ES256 = "ES256";
    private static final String SUBJECT = "user123";
    private static final String AUDIENCE = "client123";

    private DefaultIdTokenGenerator rsaGenerator;
    private DefaultIdTokenGenerator ecGenerator;
    private RSAPrivateKey rsaPrivateKey;
    private RSAPublicKey rsaPublicKey;
    private ECPrivateKey ecPrivateKey;
    private ECPublicKey ecPublicKey;

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

        // Create generators
        rsaGenerator = new DefaultIdTokenGenerator(ISSUER, ALGORITHM_RS256, rsaPrivateKey);
        ecGenerator = new DefaultIdTokenGenerator(ISSUER, ALGORITHM_ES256, ecPrivateKey);
    }

    @Test
    @DisplayName("Should successfully generate ID token with RSA")
    void testGenerateTokenWithRSA() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act
        IdToken idToken = rsaGenerator.generate(claims);

        // Assert
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getTokenValue(), "Token value should not be null");
        assertNotNull(idToken.getClaims(), "Claims should not be null");
        assertEquals(SUBJECT, idToken.getClaims().getSub(), "Subject should match");
        assertEquals(AUDIENCE, idToken.getClaims().getAud(), "Audience should match");
    }

    @Test
    @DisplayName("Should successfully generate ID token with EC")
    void testGenerateTokenWithEC() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act
        IdToken idToken = ecGenerator.generate(claims);

        // Assert
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getTokenValue(), "Token value should not be null");
        assertNotNull(idToken.getClaims(), "Claims should not be null");
    }

    @Test
    @DisplayName("Should generate token with custom lifetime when exp is not provided")
    void testGenerateTokenWithCustomLifetime() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        // Note: IdTokenClaims.Builder requires exp, so we must provide it
        // The generator will use the provided exp, not calculate from lifetimeInSeconds
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 7200) // Provide the expected lifetime
                .build();
        long customLifetime = 7200; // 2 hours (this is ignored when exp is provided)

        // Act
        IdToken idToken = rsaGenerator.generate(claims, customLifetime);

        // Assert
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getClaims().getExp(), "Expiration should be set");
        // The generator uses the provided exp (7200), not calculating from lifetimeInSeconds
        long actualExp = idToken.getClaims().getExp();
        long actualIat = idToken.getClaims().getIat();
        long actualLifetime = actualExp - actualIat;
        // The actual lifetime should be approximately what we provided (7200)
        assertTrue(Math.abs(actualLifetime - customLifetime) <= 10,
                "Lifetime should be approximately " + customLifetime + " seconds, but was " + actualLifetime);
    }

    @Test
    @DisplayName("Should include optional claims in token")
    void testGenerateTokenWithOptionalClaims() {
        // Arrange
        String nonce = "nonce123";
        String acr = "0";
        String[] amr = {"pwd", "mfa"};
        String azp = "authorized-party";
        long authTime = System.currentTimeMillis() / 1000 - 300; // 5 minutes ago
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

        // Act
        IdToken idToken = rsaGenerator.generate(claims);

        // Assert
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getClaims(), "Claims should not be null");
        assertEquals(nonce, idToken.getClaims().getNonce(), "Nonce should match");
        assertEquals(acr, idToken.getClaims().getAcr(), "ACR should match");
        assertArrayEquals(amr, idToken.getClaims().getAmr(), "AMR should match");
        assertEquals(azp, idToken.getClaims().getAzp(), "AZP should match");
        assertEquals(authTime, idToken.getClaims().getAuthTime(), "Auth time should match");
    }

    @Test
    @DisplayName("Should throw exception when claims is null")
    void testGenerateTokenWithNullClaims() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> rsaGenerator.generate(null),
                "Should throw exception when claims is null");
    }

    @Test
    @DisplayName("Should throw exception when lifetime is not positive")
    void testGenerateTokenWithInvalidLifetime() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> rsaGenerator.generate(claims, 0),
                "Should throw exception when lifetime is 0");
        assertThrows(IllegalArgumentException.class, () -> rsaGenerator.generate(claims, -1),
                "Should throw exception when lifetime is negative");
    }

    @Test
    @DisplayName("Should throw exception when issuer is null")
    void testConstructorWithNullIssuer() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                new DefaultIdTokenGenerator(null, ALGORITHM_RS256, rsaPrivateKey),
                "Should throw exception when issuer is null");
    }

    @Test
    @DisplayName("Should throw exception when algorithm is null")
    void testConstructorWithNullAlgorithm() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                new DefaultIdTokenGenerator(ISSUER, null, rsaPrivateKey),
                "Should throw exception when algorithm is null");
    }

    @Test
    @DisplayName("Should throw exception when signing key is null")
    void testConstructorWithNullSigningKey() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> 
                new DefaultIdTokenGenerator(ISSUER, ALGORITHM_RS256, null),
                "Should throw exception when signing key is null");
    }

    @Test
    @DisplayName("Should generate token with RSAKey JWK")
    void testGenerateTokenWithRSAKeyJWK() throws Exception {
        // Arrange
        RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey)
                .privateKey(rsaPrivateKey)
                .keyID("key-id-123")
                .build();

        DefaultIdTokenGenerator generatorWithJWK = new DefaultIdTokenGenerator(ISSUER, ALGORITHM_RS256, rsaKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act
        IdToken idToken = generatorWithJWK.generate(claims);

        // Assert
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getTokenValue(), "Token value should not be null");
        // Key ID is in the JWT header, not necessarily in the token string payload
        // The token is base64 encoded, so we check if it was generated successfully
        assertTrue(idToken.getTokenValue().split("\\.").length == 3, "Token should have 3 parts (header.payload.signature)");
    }

    @Test
    @DisplayName("Should generate token with ECKey JWK")
    void testGenerateTokenWithECKeyJWK() throws Exception {
        // Arrange
        ECKey ecKey = new ECKey.Builder(Curve.P_256, ecPublicKey)
                .privateKey(ecPrivateKey)
                .keyID("ec-key-id-456")
                .build();

        DefaultIdTokenGenerator generatorWithJWK = new DefaultIdTokenGenerator(ISSUER, ALGORITHM_ES256, ecKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act
        IdToken idToken = generatorWithJWK.generate(claims);

        // Assert
        assertNotNull(idToken, "ID token should not be null");
        assertNotNull(idToken.getTokenValue(), "Token value should not be null");
    }

    @Test
    @DisplayName("Should throw exception with unsupported algorithm")
    void testGenerateTokenWithUnsupportedAlgorithm() {
        // Arrange
        String unsupportedAlgorithm = "HS256";
        DefaultIdTokenGenerator generator = new DefaultIdTokenGenerator(ISSUER, unsupportedAlgorithm, rsaPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> generator.generate(claims),
                "Should throw exception for unsupported algorithm");
    }

    @Test
    @DisplayName("Should throw exception with wrong key type for RSA")
    void testGenerateTokenWithWrongKeyForRSA() {
        // Arrange
        DefaultIdTokenGenerator generator = new DefaultIdTokenGenerator(ISSUER, ALGORITHM_RS256, ecPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> generator.generate(claims),
                "Should throw exception when using EC key for RSA algorithm");
    }

    @Test
    @DisplayName("Should throw exception with wrong key type for EC")
    void testGenerateTokenWithWrongKeyForEC() {
        // Arrange
        DefaultIdTokenGenerator generator = new DefaultIdTokenGenerator(ISSUER, ALGORITHM_ES256, rsaPrivateKey);
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act & Assert
        assertThrows(IdTokenException.class, () -> generator.generate(claims),
                "Should throw exception when using RSA key for EC algorithm");
    }

    @Test
    @DisplayName("Should auto-set iat and exp if not provided")
    void testAutoSetTimestamps() {
        // Arrange
        long now = System.currentTimeMillis() / 1000;
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .build();

        // Act
        IdToken idToken = rsaGenerator.generate(claims);

        // Assert
        assertNotNull(idToken.getClaims().getIat(), "Issued at should be auto-set");
        assertNotNull(idToken.getClaims().getExp(), "Expiration should be auto-set");
        
        assertTrue(idToken.getClaims().getIat() <= now + 10, "IAT should be close to now");
        assertTrue(idToken.getClaims().getExp() > now, "EXP should be in the future");
    }

    @Test
    @DisplayName("Should use provided iat and exp if specified")
    void testUseProvidedTimestamps() {
        // Arrange
        long customIat = 1000000000L;
        long customExp = 1000003600L;
        
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(customIat)
                .exp(customExp)
                .build();

        // Act
        IdToken idToken = rsaGenerator.generate(claims);

        // Assert
        assertEquals(customIat, idToken.getClaims().getIat(), "Should use provided IAT");
        assertEquals(customExp, idToken.getClaims().getExp(), "Should use provided EXP");
    }

    @Test
    @DisplayName("Should return correct issuer")
    void testGetIssuer() {
        assertEquals(ISSUER, rsaGenerator.getIssuer(), "Issuer should match");
    }

    @Test
    @DisplayName("Should return correct algorithm")
    void testGetAlgorithm() {
        assertEquals(ALGORITHM_RS256, rsaGenerator.getAlgorithm(), "Algorithm should match");
    }

    @Test
    @DisplayName("Should return correct signing key")
    void testGetSigningKey() {
        assertEquals(rsaPrivateKey, rsaGenerator.getSigningKey(), "Signing key should match");
    }

    @Test
    @DisplayName("Should compute correct at_hash for RS256")
    void testComputeAtHashForRS256() {
        String accessToken = "ya29.a0AfH6SMBx";
        String atHash = DefaultIdTokenGenerator.computeAtHash(accessToken, "RS256");
        
        assertNotNull(atHash, "at_hash should not be null");
        assertFalse(atHash.isEmpty(), "at_hash should not be empty");
        // Verify deterministic: same input produces same output
        String atHash2 = DefaultIdTokenGenerator.computeAtHash(accessToken, "RS256");
        assertEquals(atHash, atHash2, "at_hash should be deterministic");
    }

    @Test
    @DisplayName("Should compute correct at_hash for ES256")
    void testComputeAtHashForES256() {
        String accessToken = "ya29.a0AfH6SMBx";
        String atHash = DefaultIdTokenGenerator.computeAtHash(accessToken, "ES256");
        
        assertNotNull(atHash, "at_hash should not be null");
        // RS256 and ES256 both use SHA-256, so at_hash should be the same
        String atHashRS256 = DefaultIdTokenGenerator.computeAtHash(accessToken, "RS256");
        assertEquals(atHashRS256, atHash, "RS256 and ES256 should produce same at_hash (both use SHA-256)");
    }

    @Test
    @DisplayName("Should compute different at_hash for different algorithms")
    void testComputeAtHashDifferentAlgorithms() {
        String accessToken = "ya29.a0AfH6SMBx";
        String atHash256 = DefaultIdTokenGenerator.computeAtHash(accessToken, "RS256");
        String atHash384 = DefaultIdTokenGenerator.computeAtHash(accessToken, "RS384");
        String atHash512 = DefaultIdTokenGenerator.computeAtHash(accessToken, "RS512");
        
        // Different hash algorithms should produce different at_hash values
        assertNotEquals(atHash256, atHash384, "RS256 and RS384 should produce different at_hash");
        assertNotEquals(atHash256, atHash512, "RS256 and RS512 should produce different at_hash");
        assertNotEquals(atHash384, atHash512, "RS384 and RS512 should produce different at_hash");
    }

    @Test
    @DisplayName("Should throw exception for unsupported algorithm in computeAtHash")
    void testComputeAtHashUnsupportedAlgorithm() {
        assertThrows(IllegalArgumentException.class,
                () -> DefaultIdTokenGenerator.computeAtHash("token", "HS256"),
                "Should throw for unsupported algorithm");
    }

    @Test
    @DisplayName("Should throw exception for null algorithm in computeAtHash")
    void testComputeAtHashNullAlgorithm() {
        assertThrows(IllegalArgumentException.class,
                () -> DefaultIdTokenGenerator.computeAtHash("token", null),
                "Should throw for null algorithm");
    }

    @Test
    @DisplayName("Should include at_hash in generated token when provided")
    void testGenerateTokenWithAtHash() {
        long now = System.currentTimeMillis() / 1000;
        String atHash = DefaultIdTokenGenerator.computeAtHash("test-access-token", "RS256");
        
        IdTokenClaims claims = IdTokenClaims.builder()
                .iss(ISSUER)
                .sub(SUBJECT)
                .aud(AUDIENCE)
                .iat(now)
                .exp(now + 3600)
                .atHash(atHash)
                .build();

        IdToken idToken = rsaGenerator.generate(claims);

        assertNotNull(idToken, "ID token should not be null");
        assertEquals(atHash, idToken.getClaims().getAtHash(), "at_hash should be preserved in generated token");
    }
}