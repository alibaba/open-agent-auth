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
package com.alibaba.openagentauth.core.token.aoat;

import com.alibaba.openagentauth.core.model.audit.AuditTrail;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.References;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AoatSerializer}.
 * <p>
 * Tests the serializer's behavior including:
 * <ul>
 *   <li>Serializing tokens with required and optional claims</li>
 *   <li>Handling different signing keys (with and without kid)</li>
 *   <li>Error handling for null parameters</li>
 *   <li>Edge cases for serialization</li>
 * </ul>
 * </p>
 */
@DisplayName("AoatSerializer Tests")
class AoatSerializerTest {

    private RSAKey signingKey;
    private JWSSigner signer;
    private JWSAlgorithm algorithm;
    private AgentOperationAuthToken testToken;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for signing
        signingKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();
        signer = new RSASSASigner(signingKey);
        algorithm = JWSAlgorithm.RS256;

        // Create test token with all claims
        testToken = createTestToken();
    }

    @Nested
    @DisplayName("Serialization Tests")
    class SerializationTests {

        @Test
        @DisplayName("Should serialize token with all claims successfully")
        void shouldSerializeTokenWithAllClaimsSuccessfully() throws JOSEException {
            String jwtString = AoatSerializer.serialize(testToken, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString.split("\\.")).hasSize(3); // header.payload.signature
        }

        @Test
        @DisplayName("Should serialize token with only required claims")
        void shouldSerializeTokenWithOnlyRequiredClaims() throws JOSEException {
            AgentOperationAuthToken token = createMinimalToken();
            String jwtString = AoatSerializer.serialize(token, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString.split("\\.")).hasSize(3);
        }

        @Test
        @DisplayName("Should serialize token without key ID in signing key")
        void shouldSerializeTokenWithoutKeyIdInSigningKey() throws JOSEException {
            RSAKey keyWithoutKid = new RSAKeyGenerator(2048).generate();
            JWSSigner signerWithoutKid = new RSASSASigner(keyWithoutKid);

            String jwtString = AoatSerializer.serialize(testToken, signerWithoutKid, algorithm, keyWithoutKid);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }

        @Test
        @DisplayName("Should serialize token with delegation chain")
        void shouldSerializeTokenWithDelegationChain() throws JOSEException {
            AgentOperationAuthToken token = createTokenWithDelegationChain();
            String jwtString = AoatSerializer.serialize(token, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }

        @Test
        @DisplayName("Should serialize token with null optional claims")
        void shouldSerializeTokenWithNullOptionalClaims() throws JOSEException {
            AgentOperationAuthToken token = AgentOperationAuthToken.builder()
                    .header(AgentOperationAuthToken.Header.builder()
                            .type("JWT")
                            .algorithm("RS256")
                            .build())
                    .claims(AgentOperationAuthToken.Claims.builder()
                            .issuer("https://issuer.example.com")
                            .subject("user123")
                            .audience("https://audience.example.com")
                            .issuedAt(Instant.now())
                            .expirationTime(Instant.now().plusSeconds(3600))
                            .jwtId("test-jti-001")
                            .agentIdentity(createAgentIdentity())
                            .authorization(AgentOperationAuthorization.builder()
                                    .policyId("policy-123")
                                    .build())
                            .evidence(null)
                            .context(null)
                            .auditTrail(null)
                            .references(null)
                            .delegationChain(null)
                            .build())
                    .build();

            String jwtString = AoatSerializer.serialize(token, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when token is null")
        void shouldThrowExceptionWhenTokenIsNull() {
            assertThatThrownBy(() -> AoatSerializer.serialize(null, signer, algorithm, signingKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("AgentOperationAuthToken cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when signer is null")
        void shouldThrowExceptionWhenSignerIsNull() {
            assertThatThrownBy(() -> AoatSerializer.serialize(testToken, null, algorithm, signingKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("JWSSigner cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() {
            assertThatThrownBy(() -> AoatSerializer.serialize(testToken, signer, null, signingKey))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("JWSAlgorithm cannot be null");
        }

        @Test
        @DisplayName("Should handle null signing key gracefully")
        void shouldHandleNullSigningKeyGracefully() throws JOSEException {
            // Note: The serializer accepts null signing key, but it won't have a kid in the header
            String jwtString = AoatSerializer.serialize(testToken, signer, algorithm, null);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle token with empty delegation chain")
        void shouldHandleTokenWithEmptyDelegationChain() throws JOSEException {
            AgentOperationAuthToken token = AgentOperationAuthToken.builder()
                    .header(AgentOperationAuthToken.Header.builder()
                            .type("JWT")
                            .algorithm("RS256")
                            .build())
                    .claims(AgentOperationAuthToken.Claims.builder()
                            .issuer("https://issuer.example.com")
                            .subject("user123")
                            .audience("https://audience.example.com")
                            .issuedAt(Instant.now())
                            .expirationTime(Instant.now().plusSeconds(3600))
                            .jwtId("test-jti-001")
                            .agentIdentity(createAgentIdentity())
                            .authorization(AgentOperationAuthorization.builder()
                                    .policyId("policy-123")
                                    .build())
                            .delegationChain(List.of())
                            .build())
                    .build();

            String jwtString = AoatSerializer.serialize(token, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }

        @Test
        @DisplayName("Should handle token with very long strings")
        void shouldHandleTokenWithVeryLongStrings() throws JOSEException {
            String longString = "a".repeat(10000);
            
            AgentOperationAuthToken token = AgentOperationAuthToken.builder()
                    .header(AgentOperationAuthToken.Header.builder()
                            .type("JWT")
                            .algorithm("RS256")
                            .build())
                    .claims(AgentOperationAuthToken.Claims.builder()
                            .issuer("https://issuer.example.com")
                            .subject("user123")
                            .audience("https://audience.example.com")
                            .issuedAt(Instant.now())
                            .expirationTime(Instant.now().plusSeconds(3600))
                            .jwtId("test-jti-001")
                            .agentIdentity(createAgentIdentity())
                            .authorization(AgentOperationAuthorization.builder()
                                    .policyId(longString)
                                    .build())
                            .context(TokenAuthorizationContext.builder()
                                    .renderedText(longString)
                                    .build())
                            .build())
                    .build();

            String jwtString = AoatSerializer.serialize(token, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }

        @Test
        @DisplayName("Should handle token with special characters in claims")
        void shouldHandleTokenWithSpecialCharactersInClaims() throws JOSEException {
            String specialChars = "special-characters!@#$%^&*()_+-=[]{}|;':\",./<>?";
            
            AgentOperationAuthToken token = AgentOperationAuthToken.builder()
                    .header(AgentOperationAuthToken.Header.builder()
                            .type("JWT")
                            .algorithm("RS256")
                            .build())
                    .claims(AgentOperationAuthToken.Claims.builder()
                            .issuer("https://issuer.example.com")
                            .subject("user123")
                            .audience("https://audience.example.com")
                            .issuedAt(Instant.now())
                            .expirationTime(Instant.now().plusSeconds(3600))
                            .jwtId(specialChars)
                            .agentIdentity(createAgentIdentity())
                            .authorization(AgentOperationAuthorization.builder()
                                    .policyId(specialChars)
                                    .build())
                            .build())
                    .build();

            String jwtString = AoatSerializer.serialize(token, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Signing Key Tests")
    class SigningKeyTests {

        @Test
        @DisplayName("Should use key ID from signing key when present")
        void shouldUseKeyIdFromSigningKeyWhenPresent() throws JOSEException {
            String jwtString = AoatSerializer.serialize(testToken, signer, algorithm, signingKey);

            assertThat(jwtString).isNotNull();
            // The key ID should be in the header (first part of JWT)
            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("test-key-id");
        }

        @Test
        @DisplayName("Should work with different key sizes")
        void shouldWorkWithDifferentKeySizes() throws JOSEException {
            RSAKey key4096 = new RSAKeyGenerator(4096)
                    .keyID("key-4096")
                    .generate();
            JWSSigner signer4096 = new RSASSASigner(key4096);

            String jwtString = AoatSerializer.serialize(testToken, signer4096, algorithm, key4096);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }
    }

    // Helper methods

    private AgentOperationAuthToken createTestToken() {
        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .type("JWT")
                        .algorithm("RS256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://issuer.example.com")
                        .subject("user123")
                        .audience("https://audience.example.com")
                        .issuedAt(Instant.now())
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .jwtId("test-jti-001")
                        .agentIdentity(createAgentIdentity())
                        .authorization(AgentOperationAuthorization.builder()
                                .policyId("policy-123")
                                .build())
                        .evidence(Evidence.builder()
                                .sourcePromptCredential("test-credential")
                                .build())
                        .context(TokenAuthorizationContext.builder()
                                .renderedText("Test operation")
                                .build())
                        .auditTrail(AuditTrail.builder()
                                .originalPromptText("Test prompt")
                                .renderedOperationText("Test operation")
                                .semanticExpansionLevel("level-1")
                                .userAcknowledgeTimestamp("2024-01-01T00:00:00Z")
                                .consentInterfaceVersion("1.0")
                                .build())
                        .references(References.builder()
                                .relatedProposalId("proposal-123")
                                .build())
                        .build())
                .build();
    }

    private AgentOperationAuthToken createMinimalToken() {
        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .type("JWT")
                        .algorithm("RS256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://issuer.example.com")
                        .subject("user123")
                        .audience("https://audience.example.com")
                        .issuedAt(Instant.now())
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .jwtId("test-jti-001")
                        .agentIdentity(createAgentIdentity())
                        .authorization(AgentOperationAuthorization.builder()
                                .policyId("policy-123")
                                .build())
                        .build())
                .build();
    }

    private AgentOperationAuthToken createTokenWithDelegationChain() {
        DelegationChain delegationChain = DelegationChain.builder()
                .delegatorJti("delegator-jti-001")
                .delegatorAgentIdentity(createAgentIdentity())
                .delegationTimestamp(Instant.now())
                .operationSummary("Test delegation")
                .asSignature("test-signature")
                .build();

        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .type("JWT")
                        .algorithm("RS256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://issuer.example.com")
                        .subject("user123")
                        .audience("https://audience.example.com")
                        .issuedAt(Instant.now())
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .jwtId("test-jti-001")
                        .agentIdentity(createAgentIdentity())
                        .authorization(AgentOperationAuthorization.builder()
                                .policyId("policy-123")
                                .build())
                        .delegationChain(List.of(delegationChain))
                        .build())
                .build();
    }

    private AgentIdentity createAgentIdentity() {
        return AgentIdentity.builder()
                .version("1.0")
                .id("agent-001")
                .issuer("https://issuer.example.com")
                .issuedTo("user123")
                .issuedFor(AgentIdentity.IssuedFor.builder()
                        .platform("test-platform")
                        .client("test-client")
                        .clientInstance("test-instance")
                        .build())
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(86400))
                .build();
    }
}
