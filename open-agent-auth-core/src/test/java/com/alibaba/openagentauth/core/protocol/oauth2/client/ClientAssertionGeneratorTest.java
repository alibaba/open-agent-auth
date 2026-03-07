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
package com.alibaba.openagentauth.core.protocol.oauth2.client;

import com.alibaba.openagentauth.core.exception.oauth2.ClientAssertionException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for ClientAssertionGenerator.
 * <p>
 * This test class verifies the functionality of generating OAuth 2.0 client
 * assertions according to RFC 7523 specification.
 * </p>
 */
@DisplayName("ClientAssertionGenerator Tests")
class ClientAssertionGeneratorTest {

    private ClientAssertionGenerator generator;
    private RSAKey signingKey;
    private String clientId;

    @BeforeEach
    void setUp() throws JOSEException {
        clientId = "test-client-123";
        signingKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();
        generator = new ClientAssertionGenerator(clientId, signingKey, JWSAlgorithm.RS256);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create generator with valid parameters")
        void shouldCreateGeneratorWithValidParameters() {
            assertThat(generator).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when clientId is null")
        void shouldThrowExceptionWhenClientIdIsNull() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            
            assertThatThrownBy(() -> new ClientAssertionGenerator(null, key, JWSAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw exception when clientId is empty")
        void shouldThrowExceptionWhenClientIdIsEmpty() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            
            assertThatThrownBy(() -> new ClientAssertionGenerator("", key, JWSAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw exception when clientId is whitespace")
        void shouldThrowExceptionWhenClientIdIsWhitespace() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            
            assertThatThrownBy(() -> new ClientAssertionGenerator("   ", key, JWSAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw exception when signingKey is null")
        void shouldThrowExceptionWhenSigningKeyIsNull() {
            assertThatThrownBy(() -> new ClientAssertionGenerator(clientId, null, JWSAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signing key");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() throws JOSEException {
            RSAKey key = new RSAKeyGenerator(2048).keyID("key").generate();
            
            assertThatThrownBy(() -> new ClientAssertionGenerator(clientId, key, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Algorithm");
        }
    }

    @Nested
    @DisplayName("Generate Assertion Tests")
    class GenerateAssertionTests {

        @Test
        @DisplayName("Should generate valid assertion with default expiration")
        void shouldGenerateValidAssertionWithDefaultExpiration() throws ClientAssertionException, JOSEException, ParseException {
            String tokenEndpoint = "https://example.com/token";
            
            String assertion = generator.generateAssertion(tokenEndpoint);
            
            assertThat(assertion).isNotNull();
            assertThat(assertion).isNotEmpty();
            
            // Verify JWT structure
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getHeader().getKeyID()).isEqualTo("test-key-id");
            assertThat(signedJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
            
            // Verify claims
            assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo(clientId);
            assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo(clientId);
            assertThat(signedJwt.getJWTClaimsSet().getAudience()).containsExactly(tokenEndpoint);
            assertThat(signedJwt.getJWTClaimsSet().getJWTID()).isNotEmpty();
        }

        @Test
        @DisplayName("Should generate valid assertion with custom expiration")
        void shouldGenerateValidAssertionWithCustomExpiration() throws ClientAssertionException, JOSEException, ParseException {
            String tokenEndpoint = "https://example.com/token";
            long customExpiration = 600; // 10 minutes
            
            String assertion = generator.generateAssertion(tokenEndpoint, customExpiration);
            
            assertThat(assertion).isNotNull();
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            long expTime = signedJwt.getJWTClaimsSet().getExpirationTime().getTime();
            long iatTime = signedJwt.getJWTClaimsSet().getIssueTime().getTime();
            assertThat(expTime - iatTime).isEqualTo(customExpiration * 1000);
        }

        @Test
        @DisplayName("Should throw exception when tokenEndpoint is null")
        void shouldThrowExceptionWhenTokenEndpointIsNull() {
            assertThatThrownBy(() -> generator.generateAssertion(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token endpoint");
        }

        @Test
        @DisplayName("Should throw exception when tokenEndpoint is empty")
        void shouldThrowExceptionWhenTokenEndpointIsEmpty() {
            assertThatThrownBy(() -> generator.generateAssertion(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token endpoint");
        }

        @Test
        @DisplayName("Should throw exception when tokenEndpoint is whitespace")
        void shouldThrowExceptionWhenTokenEndpointIsWhitespace() {
            assertThatThrownBy(() -> generator.generateAssertion("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Token endpoint");
        }

        @Test
        @DisplayName("Should throw exception when expiration is negative")
        void shouldThrowExceptionWhenExpirationIsNegative() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", -1))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expiration is zero")
        void shouldThrowExceptionWhenExpirationIsZero() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should include jti claim")
        void shouldIncludeJtiClaim() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token");
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getJWTID()).isNotEmpty();
        }

        @Test
        @DisplayName("Should include iat claim")
        void shouldIncludeIatClaim() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token");
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getIssueTime()).isNotNull();
        }

        @Test
        @DisplayName("Should include exp claim")
        void shouldIncludeExpClaim() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token");
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
        }

        @Test
        @DisplayName("Should set issuer equal to subject")
        void shouldSetIssuerEqualToSubject() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token");
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getIssuer())
                    .isEqualTo(signedJwt.getJWTClaimsSet().getSubject());
        }

        @Test
        @DisplayName("Should verify signature")
        void shouldVerifySignature() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token");
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            RSASSAVerifier verifier = new RSASSAVerifier(signingKey);
            assertThat(signedJwt.verify(verifier)).isTrue();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle very short expiration time")
        void shouldHandleVeryShortExpirationTime() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token", 1);
            
            assertThat(assertion).isNotNull();
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
        }

        @Test
        @DisplayName("Should handle very long expiration time")
        void shouldHandleVeryLongExpirationTime() throws ClientAssertionException, JOSEException, ParseException {
            String assertion = generator.generateAssertion("https://example.com/token", 86400); // 24 hours
            
            assertThat(assertion).isNotNull();
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getExpirationTime()).isNotNull();
        }

        @Test
        @DisplayName("Should handle URL with special characters")
        void shouldHandleUrlWithSpecialCharacters() throws ClientAssertionException, JOSEException, ParseException {
            String tokenEndpoint = "https://example.com/token?param=value&other=test";
            
            String assertion = generator.generateAssertion(tokenEndpoint);
            
            assertThat(assertion).isNotNull();
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            assertThat(signedJwt.getJWTClaimsSet().getAudience()).containsExactly(tokenEndpoint);
        }
    }

    @Nested
    @DisplayName("DCR Dynamic Client ID Tests")
    class DcrDynamicClientIdTests {

        @Test
        @DisplayName("Should generate assertion with dynamic client_id (two-parameter overload)")
        void shouldGenerateAssertionWithDynamicClientId() throws ClientAssertionException, JOSEException, ParseException {
            String tokenEndpoint = "https://example.com/token";
            String dcrClientId = "dcr-dynamic-client-456";
            
            String assertion = generator.generateAssertion(tokenEndpoint, dcrClientId);
            
            assertThat(assertion).isNotNull();
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            // Verify that iss and sub use the dynamic client_id, not the default one
            assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo(dcrClientId);
            assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo(dcrClientId);
            assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isNotEqualTo(clientId);
            assertThat(signedJwt.getJWTClaimsSet().getAudience()).containsExactly(tokenEndpoint);
        }

        @Test
        @DisplayName("Should generate assertion with dynamic client_id and custom expiration (three-parameter overload)")
        void shouldGenerateAssertionWithDynamicClientIdAndCustomExpiration() throws ClientAssertionException, JOSEException, ParseException {
            String tokenEndpoint = "https://example.com/token";
            String dcrClientId = "dcr-dynamic-client-789";
            long customExpiration = 900; // 15 minutes
            
            String assertion = generator.generateAssertion(tokenEndpoint, dcrClientId, customExpiration);
            
            assertThat(assertion).isNotNull();
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            // Verify dynamic client_id is used
            assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo(dcrClientId);
            assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo(dcrClientId);
            // Verify custom expiration time
            long expTime = signedJwt.getJWTClaimsSet().getExpirationTime().getTime();
            long iatTime = signedJwt.getJWTClaimsSet().getIssueTime().getTime();
            assertThat(expTime - iatTime).isEqualTo(customExpiration * 1000);
        }

        @Test
        @DisplayName("Should throw exception when effectiveClientId is null")
        void shouldThrowExceptionWhenEffectiveClientIdIsNull() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", (String) null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Effective client ID");
        }

        @Test
        @DisplayName("Should throw exception when effectiveClientId is empty")
        void shouldThrowExceptionWhenEffectiveClientIdIsEmpty() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Effective client ID");
        }

        @Test
        @DisplayName("Should throw exception when effectiveClientId is whitespace")
        void shouldThrowExceptionWhenEffectiveClientIdIsWhitespace() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", "   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Effective client ID");
        }

        @Test
        @DisplayName("Should throw exception when effectiveClientId is null with custom expiration")
        void shouldThrowExceptionWhenEffectiveClientIdIsNullWithCustomExpiration() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", null, 300))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Effective client ID");
        }

        @Test
        @DisplayName("Should throw exception when effectiveClientId is empty with custom expiration")
        void shouldThrowExceptionWhenEffectiveClientIdIsEmptyWithCustomExpiration() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", "", 300))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Effective client ID");
        }

        @Test
        @DisplayName("Should throw exception when expiration is negative with dynamic client_id")
        void shouldThrowExceptionWhenExpirationIsNegativeWithDynamicClientId() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", "dynamic-client", -1))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expiration is zero with dynamic client_id")
        void shouldThrowExceptionWhenExpirationIsZeroWithDynamicClientId() {
            assertThatThrownBy(() -> generator.generateAssertion("https://example.com/token", "dynamic-client", 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should verify signature with dynamic client_id assertion")
        void shouldVerifySignatureWithDynamicClientId() throws ClientAssertionException, JOSEException, ParseException {
            String dcrClientId = "dcr-dynamic-client-123";
            String assertion = generator.generateAssertion("https://example.com/token", dcrClientId);
            
            SignedJWT signedJwt = SignedJWT.parse(assertion);
            RSASSAVerifier verifier = new RSASSAVerifier(signingKey);
            assertThat(signedJwt.verify(verifier)).isTrue();
        }
    }
}