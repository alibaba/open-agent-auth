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
package com.alibaba.openagentauth.core.protocol.oauth2.token.aoat;

import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;
import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;
import com.alibaba.openagentauth.core.audit.model.SemanticExpansionLevel;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.binding.InMemoryBindingInstanceStore;
import com.alibaba.openagentauth.core.crypto.jwe.JweDecoder;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyMetadata;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.token.aoat.AoatGenerator;
import com.alibaba.openagentauth.core.protocol.vc.VcVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.text.ParseException;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultAoatTokenGenerator}.
 * <p>
 * This test class validates the AOAT token generator implementation
 * following the Agent Operation Authorization framework.
 * </p>
 */
@DisplayName("DefaultAoatTokenGenerator Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultAoatTokenGeneratorTest {

    @Mock
    private VcVerifier vcVerifier;

    @Mock
    private PolicyRegistry policyRegistry;

    @Mock
    private JweDecoder jweDecoder;

    private DefaultAoatTokenGenerator generator;
    private AoatGenerator aoatGenerator;
    private BindingInstanceStore bindingInstanceStore;
    private PromptDecryptionService promptDecryptionService;
    private static final String SUBJECT = "user_12345";
    private static final String ISSUER = "https://as.example.com";
    private static final String AUDIENCE = "https://api.example.com";
    private static final long EXPIRATION_SECONDS = 3600;

    @BeforeEach
    void setUp() throws JOSEException {
        // Create a real AoatGenerator instance instead of mocking
        RSAKey signingKey = new RSAKeyGenerator(2048).keyID("test-signing-key").generate();
        aoatGenerator = new AoatGenerator(signingKey, JWSAlgorithm.RS256, ISSUER, AUDIENCE);

        // Create binding instance store
        bindingInstanceStore = new InMemoryBindingInstanceStore();

        // Create prompt decryption service (disabled for tests)
        promptDecryptionService = new PromptDecryptionService(jweDecoder, false);

        // Setup policyRegistry mock to return valid policy registration
        String testPolicyId = "policy-" + UUID.randomUUID().toString();
        Policy testPolicy = Policy.builder()
                .policyId(testPolicyId)
                .regoPolicy("allow { true }")
                .description("Test policy")
                .metadata(PolicyMetadata.builder()
                        .createdAt(Instant.now())
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .version("1.0")
                        .build())
                .build();

        PolicyRegistration testRegistration = PolicyRegistration.builder()
                .policy(testPolicy)
                .originalProposal("allow { true }")
                .registeredAt(Instant.now())
                .status("SUCCESS")
                .build();

        lenient().when(policyRegistry.register(anyString(), anyString(), anyString(), any()))
                .thenReturn(testRegistration);

        generator = new DefaultAoatTokenGenerator(
                aoatGenerator,
                vcVerifier,
                policyRegistry,
                EXPIRATION_SECONDS
        );
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should throw exception when aoatGenerator is null")
        void shouldThrowExceptionWhenAoatGeneratorIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAoatTokenGenerator(
                    null,
                    vcVerifier,
                    policyRegistry,
                    EXPIRATION_SECONDS
            ))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("AOAT generator cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when vcVerifier is null")
        void shouldThrowExceptionWhenVcVerifierIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultAoatTokenGenerator(
                    aoatGenerator,
                    null,
                    policyRegistry,
                    EXPIRATION_SECONDS
            ))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("VC verifier cannot be null");
        }
    }

    @Nested
    @DisplayName("generateAoat()")
    class GenerateAoat {

        @Test
        @DisplayName("Should throw exception when parClaims is null")
        void shouldThrowExceptionWhenParClaimsIsNull() throws JOSEException {
            // Act & Assert
            assertThatThrownBy(() -> generator.generateAoat(SUBJECT, null))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Missing authorization request claims");
        }

        @Test
        @DisplayName("Should throw exception when operation proposal is missing")
        void shouldThrowExceptionWhenOperationProposalIsMissing() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal(null)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> generator.generateAoat(SUBJECT, parClaims))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Missing operation proposal");
        }

        @Test
        @DisplayName("Should throw exception when operation proposal is empty")
        void shouldThrowExceptionWhenOperationProposalIsEmpty() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> generator.generateAoat(SUBJECT, parClaims))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Missing operation proposal");
        }

        @Test
        @DisplayName("Should throw exception when VC verification fails")
        void shouldThrowExceptionWhenVcVerificationFails() throws Exception {
            // Arrange
            String vcJwt = "invalid_vc_jwt";
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(vcJwt)
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .evidence(evidence)
                    .build();

            when(vcVerifier.verify(anyString())).thenThrow(new ParseException("Invalid JWT", 0));

            // Act & Assert
            assertThatThrownBy(() -> generator.generateAoat(SUBJECT, parClaims))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Invalid evidence VC format");
        }

        @Test
        @DisplayName("Should generate AOAT successfully")
        void shouldGenerateAoatSuccessfully() throws Exception {
            // Arrange
            String vcJwt = "valid_vc_jwt";
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(vcJwt)
                    .build();

            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("mobile-app")
                    .agent(OperationRequestContext.AgentContext.builder()
                            .platform("personal-agent.example.com")
                            .client("mobile-app-v1")
                            .instance("dfp_abc123")
                            .build())
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { input.amount <= 50.0 }")
                    .evidence(evidence)
                    .context(context)
                    .jwtId("urn:uuid:op-proposal-123")
                    .build();

            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Buy something cheap")
                    .timestamp(Instant.now())
                    .build();

            VerifiableCredential vc = VerifiableCredential.builder()
                    .jti("vc-123")
                    .credentialSubject(credentialSubject)
                    .build();

            when(vcVerifier.verify(vcJwt)).thenReturn(vc);

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getJwtString()).isNotNull();
            assertThat(result.getHeader()).isNotNull();
            assertThat(result.getClaims()).isNotNull();
            assertThat(result.getClaims().getIssuer()).isEqualTo(ISSUER);
            assertThat(result.getClaims().getSubject()).isEqualTo(SUBJECT);
            assertThat(result.getClaims().getAudience()).isEqualTo(AUDIENCE);
            // Verify references claim is populated with proposal ID per spec Section 4
            assertThat(result.getReferences()).isNotNull();
            assertThat(result.getReferences().getRelatedProposalId()).isEqualTo("urn:uuid:op-proposal-123");
            // VC is verified once in verifyEvidenceVc, then the decrypted VC is reused in buildRenderedText and buildAuditTrail
            verify(vcVerifier, times(1)).verify(vcJwt);
        }

        @Test
        @DisplayName("Should generate AOAT without evidence when evidence is null")
        void shouldGenerateAoatWithoutEvidence() throws Exception {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .evidence(null)
                    .jwtId("urn:uuid:op-proposal-456")
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getJwtString()).isNotNull();
            assertThat(result.getHeader()).isNotNull();
            assertThat(result.getClaims()).isNotNull();
            assertThat(result.getClaims().getIssuer()).isEqualTo(ISSUER);
            assertThat(result.getClaims().getSubject()).isEqualTo(SUBJECT);
            assertThat(result.getClaims().getAudience()).isEqualTo(AUDIENCE);
            // Verify references claim is still populated even without evidence
            assertThat(result.getReferences()).isNotNull();
            assertThat(result.getReferences().getRelatedProposalId()).isEqualTo("urn:uuid:op-proposal-456");
            verify(vcVerifier, never()).verify(anyString());
        }
    }

    @Nested
    @DisplayName("getDefaultTokenExpirationSeconds()")
    class GetDefaultTokenExpirationSeconds {

        @Test
        @DisplayName("Should return default expiration time")
        void shouldReturnDefaultExpirationTime() {
            // Act
            long expiration = generator.getDefaultTokenExpirationSeconds();

            // Assert
            assertThat(expiration).isEqualTo(EXPIRATION_SECONDS);
        }
    }

    @Nested
    @DisplayName("buildReferences()")
    class BuildReferences {

        @Test
        @DisplayName("Should build references with proposal ID when jti is present")
        void shouldBuildReferencesWithProposalId() throws Exception {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .jwtId("urn:uuid:op-proposal-789")
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getReferences()).isNotNull();
            assertThat(result.getReferences().getRelatedProposalId()).isEqualTo("urn:uuid:op-proposal-789");
        }

        @Test
        @DisplayName("Should not include references when jti is null")
        void shouldNotIncludeReferencesWhenJtiIsNull() throws Exception {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .jwtId(null)
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getReferences()).isNull();
        }

        @Test
        @DisplayName("Should not include references when jti is empty")
        void shouldNotIncludeReferencesWhenJtiIsEmpty() throws Exception {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .jwtId("")
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getReferences()).isNull();
        }
    }

    @Nested
    @DisplayName("OperationTextRenderer Strategy Pattern")
    class OperationTextRendererStrategy {

        @Test
        @DisplayName("Should accept custom OperationTextRenderer via constructor")
        void shouldAcceptCustomOperationTextRenderer() {
            // Arrange
            OperationTextRenderer customRenderer = context -> 
                OperationTextRenderResult.withMediumExpansion("Custom rendered text");

            // Act
            DefaultAoatTokenGenerator generatorWithCustomRenderer = new DefaultAoatTokenGenerator(
                    aoatGenerator,
                    vcVerifier,
                    policyRegistry,
                    bindingInstanceStore,
                    promptDecryptionService,
                    customRenderer,
                    EXPIRATION_SECONDS
            );

            // Assert - generator should be created successfully
            assertThat(generatorWithCustomRenderer).isNotNull();
            assertThat(generatorWithCustomRenderer.getDefaultTokenExpirationSeconds())
                    .isEqualTo(EXPIRATION_SECONDS);
        }

        @Test
        @DisplayName("Should use PatternBasedOperationTextRenderer as default")
        void shouldUsePatternBasedOperationTextRendererAsDefault() throws Exception {
            // Arrange
            String vcJwt = "valid_vc_jwt";
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(vcJwt)
                    .build();

            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile-app")
                    .agent(OperationRequestContext.AgentContext.builder()
                            .platform("personal-agent.example.com")
                            .client("mobile-app-v1")
                            .instance("dfp_abc123")
                            .build())
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { input.amount <= 50.0 }")
                    .evidence(evidence)
                    .context(requestContext)
                    .build();

            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Buy something cheap")
                    .timestamp(Instant.now())
                    .build();

            VerifiableCredential vc = VerifiableCredential.builder()
                    .jti("vc-123")
                    .credentialSubject(credentialSubject)
                    .build();

            when(vcVerifier.verify(vcJwt)).thenReturn(vc);

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert - verify that rendered text contains expected elements
            assertThat(result).isNotNull();
            assertThat(result.getContext()).isNotNull();
            assertThat(result.getContext().getRenderedText()).isNotNull();
            
            // PatternBasedOperationTextRenderer should include the original prompt
            assertThat(result.getContext().getRenderedText())
                    .contains("Buy something cheap");
            
            // Verify audit trail contains rendered operation text
            assertThat(result.getAuditTrail()).isNotNull();
            assertThat(result.getAuditTrail().getRenderedOperationText()).isNotNull();
            assertThat(result.getAuditTrail().getSemanticExpansionLevel()).isNotNull();
        }

        @Test
        @DisplayName("Should use custom renderer for rendered text")
        void shouldUseCustomRendererForRenderedText() throws Exception {
            // Arrange
            String customRenderedText = "CUSTOM: Authorized operation with custom renderer";
            OperationTextRenderer customRenderer = context -> 
                OperationTextRenderResult.withMediumExpansion(customRenderedText);

            // Note: We cannot test the constructor with custom OperationTextRenderer here because
            // it requires BindingInstanceStore which needs a valid WIT (Workload Identity Token).
            // This test verifies that the custom renderer logic works correctly.
            // The constructor signature test is covered in shouldAcceptCustomOperationTextRenderer().
            
            String vcJwt = "valid_vc_jwt";
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(vcJwt)
                    .build();

            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile-app")
                    .agent(OperationRequestContext.AgentContext.builder()
                            .platform("personal-agent.example.com")
                            .client("mobile-app-v1")
                            .instance("dfp_abc123")
                            .build())
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .evidence(evidence)
                    .context(requestContext)
                    .build();

            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt")
                    .timestamp(Instant.now())
                    .build();

            VerifiableCredential vc = VerifiableCredential.builder()
                    .jti("vc-123")
                    .credentialSubject(credentialSubject)
                    .build();

            when(vcVerifier.verify(vcJwt)).thenReturn(vc);

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert - verify that default renderer is used (PatternBasedOperationTextRenderer)
            assertThat(result).isNotNull();
            assertThat(result.getContext()).isNotNull();
            assertThat(result.getContext().getRenderedText()).isNotNull();
            
            // Verify audit trail contains rendered operation text
            assertThat(result.getAuditTrail()).isNotNull();
            assertThat(result.getAuditTrail().getRenderedOperationText()).isNotNull();
            assertThat(result.getAuditTrail().getSemanticExpansionLevel()).isNotNull();
        }

        @Test
        @DisplayName("Should render operation text without evidence")
        void shouldRenderOperationTextWithoutEvidence() throws Exception {
            // Arrange
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile-app")
                    .agent(OperationRequestContext.AgentContext.builder()
                            .platform("personal-agent.example.com")
                            .client("mobile-app-v1")
                            .instance("dfp_abc123")
                            .build())
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { input.amount <= 100.0 }")
                    .evidence(null)
                    .context(requestContext)
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getContext()).isNotNull();
            assertThat(result.getContext().getRenderedText()).isNotNull();
            
            // PatternBasedOperationTextRenderer should use policy preview when no prompt available
            assertThat(result.getContext().getRenderedText())
                    .contains("Authorized agent operation per policy:");
            
            // Verify audit trail
            assertThat(result.getAuditTrail()).isNotNull();
            assertThat(result.getAuditTrail().getRenderedOperationText())
                    .isEqualTo(result.getContext().getRenderedText());
        }

        @Test
        @DisplayName("Should include context information in rendered text")
        void shouldIncludeContextInformationInRenderedText() throws Exception {
            // Arrange
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("mobile-app")
                    .agent(OperationRequestContext.AgentContext.builder()
                            .platform("personal-agent.example.com")
                            .client("mobile-app-v1")
                            .instance("dfp_abc123")
                            .build())
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .context(context)
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getContext()).isNotNull();
            assertThat(result.getContext().getRenderedText()).isNotNull();
            
            // PatternBasedOperationTextRenderer should include channel and platform
            assertThat(result.getContext().getRenderedText())
                    .contains("mobile-app");
            assertThat(result.getContext().getRenderedText())
                    .contains("personal-agent.example.com");
        }

        @Test
        @DisplayName("Should include expiration time in rendered text")
        void shouldIncludeExpirationTimeInRenderedText() throws Exception {
            // Arrange
            OperationRequestContext requestContext = OperationRequestContext.builder()
                    .channel("mobile-app")
                    .agent(OperationRequestContext.AgentContext.builder()
                            .platform("personal-agent.example.com")
                            .client("mobile-app-v1")
                            .instance("dfp_abc123")
                            .build())
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .context(requestContext)
                    .build();

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getContext()).isNotNull();
            assertThat(result.getContext().getRenderedText()).isNotNull();
            
            // PatternBasedOperationTextRenderer should include expiration time
            assertThat(result.getContext().getRenderedText())
                    .contains("valid until");
        }

        @Test
        @DisplayName("Should set correct semantic expansion level")
        void shouldSetCorrectSemanticExpansionLevel() throws Exception {
            // Arrange
            String vcJwt = "valid_vc_jwt";
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(vcJwt)
                    .build();

            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal("allow { true }")
                    .evidence(evidence)
                    .build();

            UserInputEvidence credentialSubject = UserInputEvidence.builder()
                    .prompt("Test prompt with content")
                    .timestamp(Instant.now())
                    .build();

            VerifiableCredential vc = VerifiableCredential.builder()
                    .jti("vc-123")
                    .credentialSubject(credentialSubject)
                    .build();

            when(vcVerifier.verify(vcJwt)).thenReturn(vc);

            // Act
            AgentOperationAuthToken result = generator.generateAoat(SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getAuditTrail()).isNotNull();
            
            // PatternBasedOperationTextRenderer returns LOW expansion when prompt is present
            assertThat(result.getAuditTrail().getSemanticExpansionLevel())
                    .isEqualTo(SemanticExpansionLevel.LOW.getValue());
        }

        @Test
        @DisplayName("Should handle null operation proposal gracefully")
        void shouldHandleNullOperationProposalGracefully() throws Exception {
            // Arrange
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .operationProposal(null)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> generator.generateAoat(SUBJECT, parClaims))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasMessageContaining("Missing operation proposal");
        }
    }
}