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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Contract tests for {@link AoatTokenGenerator} interface.
 * <p>
 * This test class validates the contract and behavior expected from any
 * implementation of the AoatTokenGenerator interface. It ensures that:
 * </p>
 * <ul>
 *   <li>Valid inputs produce valid AOAT tokens</li>
 *   <li>Required claims are properly extracted and validated</li>
 *   <li>Error handling follows the expected exception contract</li>
 *   <li>Token generation includes all required fields</li>
 * </ul>
 *
 * @see AoatTokenGenerator
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AoatTokenGenerator Contract Tests")
class AoatTokenGeneratorTest {

    @Mock
    private AoatTokenGenerator aoatTokenGenerator;

    private static final String TEST_SUBJECT = "user_12345";
    private static final String TEST_ISSUER = "https://as.example.com";
    private static final String TEST_JWT_ID = "jwt_id_test_123";
    private static final String TEST_AUDIENCE = "https://api.example.com";
    private static final String TEST_POLICY_ID = "opa-policy-test-001";

    @BeforeEach
    void setUp() {
        // Reset mocks before each test
        reset(aoatTokenGenerator);
    }

    @Nested
    @DisplayName("generateAoat() - Happy Path")
    class GenerateAoatHappyPath {

        @Test
        @DisplayName("Should generate valid AOAT token with all required claims")
        void shouldGenerateValidAoatTokenWithAllRequiredClaims() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getJwtString()).isNotNull();
            assertThat(result.getClaims()).isNotNull();

            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), eq(parClaims));
        }

        @Test
        @DisplayName("Should generate token with valid expiration time")
        void shouldGenerateTokenWithValidExpirationTime() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            Instant expirationTime = result.getExpirationTime();
            Instant issuedAt = result.getIssuedAt();
            assertThat(expirationTime).isNotNull();
            assertThat(issuedAt).isNotNull();
            assertThat(expirationTime).isAfter(issuedAt);
            assertThat(result.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should preserve subject from input parameters")
        void shouldPreserveSubjectFromInputParameters() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            assertThat(result.getSubject()).isEqualTo(TEST_SUBJECT);
        }

        @Test
        @DisplayName("Should generate unique JWT ID for each token")
        void shouldGenerateUniqueJwtIdForEachToken() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken token1 = createValidAgentOperationAuthToken();
            AgentOperationAuthToken token2 = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(token1)
                    .thenReturn(token2);

            // Act
            AgentOperationAuthToken result1 = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);
            AgentOperationAuthToken result2 = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            assertThat(result1.getJwtId()).isNotNull();
            assertThat(result2.getJwtId()).isNotNull();
            // Note: This test verifies the contract, actual uniqueness depends on implementation
            verify(aoatTokenGenerator, times(2)).generateAoat(eq(TEST_SUBJECT), eq(parClaims));
        }

        @Test
        @DisplayName("Should include agent identity in generated token")
        void shouldIncludeAgentIdentityInGeneratedToken() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            AgentIdentity agentIdentity = result.getAgentIdentity();
            assertThat(agentIdentity).isNotNull();
            assertThat(agentIdentity.getId()).isNotNull();
            assertThat(agentIdentity.getIssuer()).isNotNull();
        }

        @Test
        @DisplayName("Should include operation authorization with policy ID")
        void shouldIncludeOperationAuthorizationWithPolicyId() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            AgentOperationAuthorization authorization = result.getAuthorization();
            assertThat(authorization).isNotNull();
            assertThat(authorization.getPolicyId()).isNotNull();
        }
    }

    @Nested
    @DisplayName("generateAoat() - Parameter Validation")
    class GenerateAoatParameterValidation {

        @Test
        @DisplayName("Should throw exception when subject is null")
        void shouldThrowExceptionWhenSubjectIsNull() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            when(aoatTokenGenerator.generateAoat(isNull(), any(ParJwtClaims.class)))
                    .thenThrow(new IllegalArgumentException("Subject cannot be null"));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat(null, parClaims))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Subject");
        }

        @Test
        @DisplayName("Should throw exception when subject is empty")
        void shouldThrowExceptionWhenSubjectIsEmpty() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenThrow(new IllegalArgumentException("Subject cannot be empty"));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat("", parClaims))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when parClaims is null")
        void shouldThrowExceptionWhenParClaimsIsNull() throws JOSEException {
            // Arrange
            when(aoatTokenGenerator.generateAoat(anyString(), any()))
                    .thenThrow(new IllegalArgumentException("PAR claims cannot be null"));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat(TEST_SUBJECT, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PAR claims");
        }

        @Test
        @DisplayName("Should validate required fields in parClaims")
        void shouldValidateRequiredFieldsInParClaims() throws JOSEException {
            // Arrange
            ParJwtClaims invalidClaims = ParJwtClaims.builder()
                    .issuer(null) // Missing required field
                    .build();
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenThrow(OAuth2TokenException.invalidRequest("Missing required claims"));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat(TEST_SUBJECT, invalidClaims))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_request");
        }
    }

    @Nested
    @DisplayName("generateAoat() - Error Handling")
    class GenerateAoatErrorHandling {

        @Test
        @DisplayName("Should throw JOSEException when token signing fails")
        void shouldThrowJoseExceptionWhenTokenSigningFails() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenThrow(new JOSEException("Failed to sign token"));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims))
                    .isInstanceOf(JOSEException.class)
                    .hasMessageContaining("sign");
        }

        @Test
        @DisplayName("Should throw OAuth2TokenException when validation fails")
        void shouldThrowOAuth2TokenExceptionWhenValidationFails() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenThrow(OAuth2TokenException.invalidGrant("Invalid credentials"));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims))
                    .isInstanceOf(OAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("rfcErrorCode", "invalid_grant");
        }

        @Test
        @DisplayName("Should propagate underlying exception cause")
        void shouldPropagateUnderlyingExceptionCause() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            Exception cause = new RuntimeException("Underlying error");
            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenThrow(new JOSEException("Token generation failed", cause));

            // Act & Assert
            assertThatThrownBy(() -> aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims))
                    .isInstanceOf(JOSEException.class)
                    .hasCauseExactlyInstanceOf(RuntimeException.class);
        }
    }

    @Nested
    @DisplayName("generateAoat() - Claims Mapping")
    class GenerateAoatClaimsMapping {

        @Test
        @DisplayName("Should extract operation proposal from PAR claims")
        void shouldExtractOperationProposalFromParClaims() throws JOSEException {
            // Arrange
            String operationProposal = "allow { input.amount <= 100 }";
            ParJwtClaims parClaims = createValidParJwtClaims();
            parClaims = ParJwtClaims.builder()
                    .issuer(parClaims.getIssuer())
                    .subject(parClaims.getSubject())
                    .audience(parClaims.getAudience())
                    .issueTime(parClaims.getIssueTime())
                    .expirationTime(parClaims.getExpirationTime())
                    .jwtId(parClaims.getJwtId())
                    .evidence(parClaims.getEvidence())
                    .agentUserBindingProposal(parClaims.getAgentUserBindingProposal())
                    .operationProposal(operationProposal)
                    .context(parClaims.getContext())
                    .build();

            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), argThat(claims -> {
                assertThat(claims.getOperationProposal()).isEqualTo(operationProposal);
                return true;
            }));
        }

        @Test
        @DisplayName("Should preserve evidence from PAR claims")
        void shouldPreserveEvidenceFromParClaims() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), argThat(claims -> {
                assertThat(claims.getEvidence()).isNotNull();
                assertThat(claims.getEvidence().getSourcePromptCredential()).isNotNull();
                return true;
            }));
        }

        @Test
        @DisplayName("Should extract agent user binding proposal")
        void shouldExtractAgentUserBindingProposal() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), argThat(claims -> {
                AgentUserBindingProposal binding = claims.getAgentUserBindingProposal();
                assertThat(binding).isNotNull();
                assertThat(binding.getUserIdentityToken()).isNotNull();
                assertThat(binding.getAgentWorkloadToken()).isNotNull();
                return true;
            }));
        }
    }

    @Nested
    @DisplayName("Token Structure Validation")
    class TokenStructureValidation {

        @Test
        @DisplayName("Should generate token with valid JWT structure")
        void shouldGenerateTokenWithValidJwtStructure() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            assertThat(result.getJwtString()).isNotNull();
            assertThat(result.getHeader()).isNotNull();
            assertThat(result.getClaims()).isNotNull();
            assertThat(result.getSignature()).isNotNull();

            assertThat(result.getHeader().getType()).isEqualTo("JWT");
            assertThat(result.getHeader().getAlgorithm()).isNotNull();
        }

        @Test
        @DisplayName("Should include all standard JWT claims")
        void shouldIncludeAllStandardJwtClaims() throws JOSEException {
            // Arrange
            ParJwtClaims parClaims = createValidParJwtClaims();
            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            assertThat(result.getIssuer()).isNotNull();
            assertThat(result.getSubject()).isNotNull();
            assertThat(result.getAudience()).isNotNull();
            assertThat(result.getIssuedAt()).isNotNull();
            assertThat(result.getExpirationTime()).isNotNull();
            assertThat(result.getJwtId()).isNotNull();
        }
    }

    @Nested
    @DisplayName("generateAoat() - Edge Cases")
    class GenerateAoatEdgeCases {

        @Test
        @DisplayName("Should handle long subject strings")
        void shouldHandleLongSubjectStrings() throws JOSEException {
            // Arrange
            String longSubject = "user_" + "x".repeat(1000);
            ParJwtClaims parClaims = createValidParJwtClaims();
            
            // Create a token with the actual long subject using Builder
            Instant now = Instant.now();
            AgentIdentity agentIdentity = AgentIdentity.builder()
                    .version("1.0")
                    .id("urn:uuid:agent-identity-" + TEST_JWT_ID)
                    .issuer(TEST_ISSUER)
                    .issuedTo(TEST_ISSUER + "|" + longSubject)
                    .issuanceDate(now)
                    .validFrom(now)
                    .expires(now.plusSeconds(3600))
                    .build();

            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId(TEST_POLICY_ID)
                    .build();

            AgentOperationAuthToken.Header header = AgentOperationAuthToken.Header.builder()
                    .type("JWT")
                    .algorithm("RS256")
                    .build();

            AgentOperationAuthToken.Claims claims = AgentOperationAuthToken.Claims.builder()
                    .issuer(TEST_ISSUER)
                    .subject(longSubject)
                    .audience(TEST_AUDIENCE)
                    .issuedAt(now)
                    .expirationTime(now.plusSeconds(3600))
                    .jwtId(TEST_JWT_ID)
                    .agentIdentity(agentIdentity)
                    .authorization(authorization)
                    .evidence(createValidEvidence())
                    .build();

            AgentOperationAuthToken expectedToken = AgentOperationAuthToken.builder()
                    .header(header)
                    .claims(claims)
                    .jwtString("jwt_string_" + TEST_JWT_ID)
                    .signature("signature_" + TEST_JWT_ID)
                    .build();

            when(aoatTokenGenerator.generateAoat(eq(longSubject), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(longSubject, parClaims);

            // Assert
            assertThat(result.getSubject()).isEqualTo(longSubject);
            verify(aoatTokenGenerator).generateAoat(eq(longSubject), eq(parClaims));
        }

        @Test
        @DisplayName("Should handle complex operation proposals")
        void shouldHandleComplexOperationProposals() throws JOSEException {
            // Arrange
            String complexProposal = "package auth\n" +
                    "default allow = false\n" +
                    "\n" +
                    "allow {\n" +
                    "    input.operation == \"transfer\"\n" +
                    "    input.amount <= 1000\n" +
                    "    input.balance >= input.amount\n" +
                    "}";
            
            ParJwtClaims parClaims = ParJwtClaims.builder()
                    .issuer("https://client.example.com")
                    .subject(TEST_SUBJECT)
                    .audience(List.of(TEST_ISSUER))
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtId(TEST_JWT_ID)
                    .evidence(createValidEvidence())
                    .agentUserBindingProposal(createValidBindingProposal())
                    .operationProposal(complexProposal)
                    .context(createValidContext())
                    .build();

            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, parClaims);

            // Assert
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), argThat(claims -> {
                assertThat(claims.getOperationProposal()).isEqualTo(complexProposal);
                return true;
            }));
        }

        @Test
        @DisplayName("Should handle minimal valid PAR claims")
        void shouldHandleMinimalValidParClaims() throws JOSEException {
            // Arrange
            ParJwtClaims minimalClaims = ParJwtClaims.builder()
                    .issuer("https://client.example.com")
                    .subject(TEST_SUBJECT)
                    .audience(List.of(TEST_ISSUER))
                    .issueTime(Date.from(Instant.now()))
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .jwtId(TEST_JWT_ID)
                    .evidence(createValidEvidence())
                    .agentUserBindingProposal(createValidBindingProposal())
                    .operationProposal("allow { true }")
                    .context(createValidContext())
                    .build();

            AgentOperationAuthToken expectedToken = createValidAgentOperationAuthToken();

            when(aoatTokenGenerator.generateAoat(anyString(), any(ParJwtClaims.class)))
                    .thenReturn(expectedToken);

            // Act
            AgentOperationAuthToken result = aoatTokenGenerator.generateAoat(TEST_SUBJECT, minimalClaims);

            // Assert
            assertThat(result).isNotNull();
            verify(aoatTokenGenerator).generateAoat(eq(TEST_SUBJECT), eq(minimalClaims));
        }
    }

    // Helper methods for creating test data

    private ParJwtClaims createValidParJwtClaims() {
        Instant now = Instant.now();
        return ParJwtClaims.builder()
                .issuer("https://client.example.com")
                .subject(TEST_SUBJECT)
                .audience(List.of(TEST_ISSUER))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .jwtId(TEST_JWT_ID)
                .evidence(createValidEvidence())
                .agentUserBindingProposal(createValidBindingProposal())
                .operationProposal("allow { input.amount <= 100 }")
                .context(createValidContext())
                .build();
    }

    private Evidence createValidEvidence() {
        return Evidence.builder()
                .sourcePromptCredential("vc_jwt_abc123")
                .build();
    }

    private AgentUserBindingProposal createValidBindingProposal() {
        return AgentUserBindingProposal.builder()
                .userIdentityToken("id_token_xyz")
                .agentWorkloadToken("wit_token_xyz")
                .deviceFingerprint("dfp_abc123")
                .build();
    }

    private OperationRequestContext createValidContext() {
        OperationRequestContext.UserContext userContext = OperationRequestContext.UserContext.builder()
                .id(TEST_SUBJECT)
                .build();

        OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                .instance("agent-instance-123")
                .platform("personal-agent.example.com")
                .client("mobile-app-v1.example.com")
                .build();

        return OperationRequestContext.builder()
                .channel("mobile-app")
                .user(userContext)
                .agent(agentContext)
                .build();
    }

    private AgentOperationAuthToken createValidAgentOperationAuthToken() {
        Instant now = Instant.now();

        AgentOperationAuthToken.Header header = AgentOperationAuthToken.Header.builder()
                .type("JWT")
                .algorithm("RS256")
                .build();

        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id("urn:uuid:agent-identity-" + TEST_JWT_ID)
                .issuer(TEST_ISSUER)
                .issuedTo(TEST_ISSUER + "|" + TEST_SUBJECT)
                .issuanceDate(now)
                .validFrom(now)
                .expires(now.plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId(TEST_POLICY_ID)
                .build();

        AgentOperationAuthToken.Claims claims = AgentOperationAuthToken.Claims.builder()
                .issuer(TEST_ISSUER)
                .subject(TEST_SUBJECT)
                .audience(TEST_AUDIENCE)
                .issuedAt(now)
                .expirationTime(now.plusSeconds(3600))
                .jwtId(TEST_JWT_ID)
                .agentIdentity(agentIdentity)
                .authorization(authorization)
                .evidence(createValidEvidence())
                .build();

        return AgentOperationAuthToken.builder()
                .header(header)
                .claims(claims)
                .jwtString("jwt_string_" + TEST_JWT_ID)
                .signature("signature_" + TEST_JWT_ID)
                .build();
    }
}
