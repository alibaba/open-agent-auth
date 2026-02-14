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
 * Unit tests for {@link AoatGenerator}.
 * <p>
 * Tests the generator's behavior including:
 * <ul>
 *   <li>Generating tokens with required and optional claims</li>
 *   <li>Using builder pattern for flexible token construction</li>
 *   <li>Generating tokens as JWT strings</li>
 *   <li>Error handling for invalid parameters</li>
 *   <li>Edge cases for token generation</li>
 * </ul>
 * </p>
 */
@DisplayName("AoatGenerator Tests")
class AoatGeneratorTest {

    private RSAKey signingKey;
    private JWSAlgorithm algorithm;
    private String issuer;
    private String audience;
    private AoatGenerator generator;

    @BeforeEach
    void setUp() throws JOSEException {
        signingKey = new RSAKeyGenerator(2048)
                .keyID("test-key-id")
                .generate();
        algorithm = JWSAlgorithm.RS256;
        issuer = "https://issuer.example.com";
        audience = "https://audience.example.com";

        generator = new AoatGenerator(signingKey, algorithm, issuer, audience);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create generator with valid parameters")
        void shouldCreateGeneratorWithValidParameters() {
            AoatGenerator newGenerator = new AoatGenerator(signingKey, algorithm, issuer, audience);

            assertThat(newGenerator).isNotNull();
            assertThat(newGenerator.getSigningKey()).isEqualTo(signingKey);
            assertThat(newGenerator.getAlgorithm()).isEqualTo(algorithm);
            assertThat(newGenerator.getIssuer()).isEqualTo(issuer);
            assertThat(newGenerator.getAudience()).isEqualTo(audience);
        }

        @Test
        @DisplayName("Should throw exception when signing key is null")
        void shouldThrowExceptionWhenSigningKeyIsNull() {
            assertThatThrownBy(() -> new AoatGenerator(null, algorithm, issuer, audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Signing key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() {
            assertThatThrownBy(() -> new AoatGenerator(signingKey, null, issuer, audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when issuer is null")
        void shouldThrowExceptionWhenIssuerIsNull() {
            assertThatThrownBy(() -> new AoatGenerator(signingKey, algorithm, null, audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Issuer cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when issuer is empty")
        void shouldThrowExceptionWhenIssuerIsEmpty() {
            assertThatThrownBy(() -> new AoatGenerator(signingKey, algorithm, "", audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Issuer cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when audience is null")
        void shouldThrowExceptionWhenAudienceIsNull() {
            assertThatThrownBy(() -> new AoatGenerator(signingKey, algorithm, issuer, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Audience cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when audience is empty")
        void shouldThrowExceptionWhenAudienceIsEmpty() {
            assertThatThrownBy(() -> new AoatGenerator(signingKey, algorithm, issuer, ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Audience cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct signing key")
        void shouldReturnCorrectSigningKey() {
            assertThat(generator.getSigningKey()).isEqualTo(signingKey);
        }

        @Test
        @DisplayName("Should return correct algorithm")
        void shouldReturnCorrectAlgorithm() {
            assertThat(generator.getAlgorithm()).isEqualTo(algorithm);
        }

        @Test
        @DisplayName("Should return correct issuer")
        void shouldReturnCorrectIssuer() {
            assertThat(generator.getIssuer()).isEqualTo(issuer);
        }

        @Test
        @DisplayName("Should return correct audience")
        void shouldReturnCorrectAudience() {
            assertThat(generator.getAudience()).isEqualTo(audience);
        }
    }

    @Nested
    @DisplayName("New Builder Tests")
    class NewBuilderTests {

        @Test
        @DisplayName("Should create builder with required parameters")
        void shouldCreateBuilderWithRequiredParameters() {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AoatGenerator.AoatBuilder builder = generator.newBuilder(
                    "user123",
                    agentIdentity,
                    authorization,
                    3600
            );

            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when subject is null in builder")
        void shouldThrowExceptionWhenSubjectIsNullInBuilder() {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AoatGenerator.AoatBuilder builder = generator.newBuilder(
                    null,
                    agentIdentity,
                    authorization,
                    3600
            );

            assertThatThrownBy(builder::build)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Subject cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when subject is empty in builder")
        void shouldThrowExceptionWhenSubjectIsEmptyInBuilder() {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AoatGenerator.AoatBuilder builder = generator.newBuilder(
                    "",
                    agentIdentity,
                    authorization,
                    3600
            );

            assertThatThrownBy(builder::build)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Subject cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Generate Aoat Tests")
    class GenerateAoatTests {

        @Test
        @DisplayName("Should generate token with required claims")
        void shouldGenerateTokenWithRequiredClaims() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);

            assertThat(token).isNotNull();
            assertThat(token.getSubject()).isEqualTo("user123");
            assertThat(token.getIssuer()).isEqualTo(issuer);
            assertThat(token.getAudience()).isEqualTo(audience);
            assertThat(token.getAgentIdentity()).isNotNull();
            assertThat(token.getAuthorization()).isNotNull();
            assertThat(token.getJwtString()).isNotNull();
            assertThat(token.getJwtString()).isNotEmpty();
            assertThat(token.getSignature()).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when agent identity is null")
        void shouldThrowExceptionWhenAgentIdentityIsNull() {
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            assertThatThrownBy(() -> generator.generateAoat("user123", null, authorization, 3600))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Agent identity cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when authorization is null")
        void shouldThrowExceptionWhenAuthorizationIsNull() {
            AgentIdentity agentIdentity = createAgentIdentity();

            assertThatThrownBy(() -> generator.generateAoat("user123", agentIdentity, null, 3600))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Authorization cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when expiration seconds is zero")
        void shouldThrowExceptionWhenExpirationSecondsIsZero() {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            assertThatThrownBy(() -> generator.generateAoat("user123", agentIdentity, authorization, 0))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expiration seconds is negative")
        void shouldThrowExceptionWhenExpirationSecondsIsNegative() {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            assertThatThrownBy(() -> generator.generateAoat("user123", agentIdentity, authorization, -100))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Expiration seconds must be positive");
        }
    }

    @Nested
    @DisplayName("Generate Aoat As String Tests")
    class GenerateAoatAsStringTests {

        @Test
        @DisplayName("Should generate token as JWT string")
        void shouldGenerateTokenAsJwtString() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            String jwtString = generator.generateAoatAsString("user123", agentIdentity, authorization, 3600);

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString.split("\\.")).hasSize(3); // header.payload.signature
        }

        @Test
        @DisplayName("Should throw exception when agent identity is null")
        void shouldThrowExceptionWhenAgentIdentityIsNullInStringMethod() {
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            assertThatThrownBy(() -> generator.generateAoatAsString("user123", null, authorization, 3600))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Agent identity cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when authorization is null")
        void shouldThrowExceptionWhenAuthorizationIsNullInStringMethod() {
            AgentIdentity agentIdentity = createAgentIdentity();

            assertThatThrownBy(() -> generator.generateAoatAsString("user123", agentIdentity, null, 3600))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Authorization cannot be null");
        }
    }

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build token with evidence")
        void shouldBuildTokenWithEvidence() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .evidence(Evidence.builder()
                            .sourcePromptCredential("test-credential")
                            .build())
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getEvidence()).isNotNull();
            assertThat(token.getEvidence().getSourcePromptCredential()).isEqualTo("test-credential");
        }

        @Test
        @DisplayName("Should build token with context")
        void shouldBuildTokenWithContext() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .context(TokenAuthorizationContext.builder()
                            .renderedText("Test operation")
                            .build())
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getContext()).isNotNull();
            assertThat(token.getContext().getRenderedText()).isEqualTo("Test operation");
        }

        @Test
        @DisplayName("Should build token with audit trail")
        void shouldBuildTokenWithAuditTrail() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .auditTrail(AuditTrail.builder()
                            .originalPromptText("Test prompt")
                            .renderedOperationText("Test operation")
                            .semanticExpansionLevel("level-1")
                            .userAcknowledgeTimestamp("2024-01-01T00:00:00Z")
                            .consentInterfaceVersion("1.0")
                            .build())
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getAuditTrail()).isNotNull();
            assertThat(token.getAuditTrail().getOriginalPromptText()).isEqualTo("Test prompt");
        }

        @Test
        @DisplayName("Should build token with references")
        void shouldBuildTokenWithReferences() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .references(References.builder()
                            .relatedProposalId("proposal-123")
                            .build())
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getReferences()).isNotNull();
            assertThat(token.getReferences().getRelatedProposalId()).isEqualTo("proposal-123");
        }

        @Test
        @DisplayName("Should build token with delegation chain")
        void shouldBuildTokenWithDelegationChain() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            DelegationChain delegationChain = DelegationChain.builder()
                    .delegatorJti("delegator-jti-001")
                    .delegatorAgentIdentity(agentIdentity)
                    .delegationTimestamp(Instant.now())
                    .operationSummary("Test delegation")
                    .asSignature("test-signature")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .delegationChain(List.of(delegationChain))
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getDelegationChain()).isNotNull();
            assertThat(token.getDelegationChain()).hasSize(1);
        }

        @Test
        @DisplayName("Should build token with all optional claims")
        void shouldBuildTokenWithAllOptionalClaims() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            DelegationChain delegationChain = DelegationChain.builder()
                    .delegatorJti("delegator-jti-001")
                    .delegatorAgentIdentity(agentIdentity)
                    .delegationTimestamp(Instant.now())
                    .operationSummary("Test delegation")
                    .asSignature("test-signature")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
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
                    .delegationChain(List.of(delegationChain))
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.getEvidence()).isNotNull();
            assertThat(token.getContext()).isNotNull();
            assertThat(token.getAuditTrail()).isNotNull();
            assertThat(token.getReferences()).isNotNull();
            assertThat(token.getDelegationChain()).isNotNull();
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AoatGenerator.AoatBuilder builder = generator.newBuilder("user123", agentIdentity, authorization, 3600);
            AoatGenerator.AoatBuilder chainedBuilder = builder
                    .evidence(Evidence.builder().sourcePromptCredential("test").build())
                    .context(TokenAuthorizationContext.builder().renderedText("test").build());

            assertThat(chainedBuilder).isNotNull();
            assertThat(chainedBuilder.build()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle very long expiration time")
        void shouldHandleVeryLongExpirationTime() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 31536000); // 1 year

            assertThat(token).isNotNull();
            assertThat(token.getExpirationTime()).isAfter(Instant.now().plusSeconds(31536000).minusSeconds(10));
        }

        @Test
        @DisplayName("Should handle very short expiration time")
        void shouldHandleVeryShortExpirationTime() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 1); // 1 second

            assertThat(token).isNotNull();
            assertThat(token.getExpirationTime()).isAfter(Instant.now());
        }

        @Test
        @DisplayName("Should handle special characters in subject")
        void shouldHandleSpecialCharactersInSubject() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            String specialSubject = "user@special!#$%^&*()";
            AgentOperationAuthToken token = generator.generateAoat(specialSubject, agentIdentity, authorization, 3600);

            assertThat(token).isNotNull();
            assertThat(token.getSubject()).isEqualTo(specialSubject);
        }

        @Test
        @DisplayName("Should handle empty delegation chain")
        void shouldHandleEmptyDelegationChain() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .delegationChain(List.of())
                    .build();

            assertThat(token).isNotNull();
            // Empty delegation chain may be null after serialization
            List<DelegationChain> delegationChain = token.getDelegationChain();
            assertThat(delegationChain == null || delegationChain.isEmpty()).isTrue();
        }

        @Test
        @DisplayName("Should generate unique JWT ID for each token")
        void shouldGenerateUniqueJwtIdForEachToken() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token1 = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            AgentOperationAuthToken token2 = generator.generateAoat("user123", agentIdentity, authorization, 3600);

            assertThat(token1.getJwtId()).isNotNull();
            assertThat(token2.getJwtId()).isNotNull();
            assertThat(token1.getJwtId()).isNotEqualTo(token2.getJwtId());
        }
    }

    @Nested
    @DisplayName("Token Structure Tests")
    class TokenStructureTests {

        @Test
        @DisplayName("Should set correct header type")
        void shouldSetCorrectHeaderType() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);

            assertThat(token.getHeader()).isNotNull();
            assertThat(token.getHeader().getType()).isEqualTo("JWT");
        }

        @Test
        @DisplayName("Should set correct algorithm in header")
        void shouldSetCorrectAlgorithmInHeader() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);

            assertThat(token.getHeader()).isNotNull();
            assertThat(token.getHeader().getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should set issued at time")
        void shouldSetIssuedAtTime() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            Instant beforeGeneration = Instant.now();
            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            Instant afterGeneration = Instant.now();

            assertThat(token.getIssuedAt()).isNotNull();
            assertThat(token.getIssuedAt()).isBetween(beforeGeneration, afterGeneration);
        }

        @Test
        @DisplayName("Should set expiration time correctly")
        void shouldSetExpirationTimeCorrectly() throws JOSEException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();
            long expirationSeconds = 3600;

            Instant expectedExpiration = Instant.now().plusSeconds(expirationSeconds);
            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, expirationSeconds);

            assertThat(token.getExpirationTime()).isNotNull();
            assertThat(token.getExpirationTime()).isBetween(expectedExpiration.minusSeconds(5), expectedExpiration.plusSeconds(5));
        }
    }

    // Helper methods

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
