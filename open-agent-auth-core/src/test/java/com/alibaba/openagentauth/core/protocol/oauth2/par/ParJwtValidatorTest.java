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
package com.alibaba.openagentauth.core.protocol.oauth2.par;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtGenerator;
import com.alibaba.openagentauth.core.model.oauth2.par.AapParParameters;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtValidator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AapParJwtValidator}.
 * Tests verify compliance with draft-liu-agent-operation-authorization-01 specification:
 * https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/
 *
 * <p>This test suite validates:</p>
 * <ul>
 *   <li>Signature verification with RS256 algorithm</li>
 *   <li>Expiration validation</li>
 *   <li>Issuer validation</li>
 *   <li>Audience validation</li>
 *   <li>Required claims validation (evidence, agent_user_binding_proposal, agent_operation_proposal, context)</li>
 *   <li>Input validation (null, empty, whitespace)</li>
 * </ul>
 */
@DisplayName("PAR-JWT Validator Tests - draft-liu-agent-operation-authorization-01")
class ParJwtValidatorTest {

    private RSAKey signingKey;
    private RSAKey verificationKey;
    private String issuer;
    private String audience;
    private AapParJwtValidator aapParJwtValidator;
    private AapParJwtGenerator aapParJwtGenerator;
    private AgentUserBindingProposal testAgentUserBindingProposal;
    private Evidence testEvidence;
    private AgentOperationProposal testOperationProposal;
    private OperationRequestContext testContext;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for PAR-JWT signing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        signingKey = rsaKeyGenerator.keyID("par-signing-key").generate();
        verificationKey = signingKey.toPublicJWK();

        // Set up issuer and audience per spec
        issuer = "https://client.myassistant.example";
        audience = "https://as.online-shop.example";
        aapParJwtValidator = new AapParJwtValidator(verificationKey, issuer, audience);
        aapParJwtGenerator = new AapParJwtGenerator(signingKey, JWSAlgorithm.RS256, issuer, audience);

        // Create test agent user binding proposal per spec
        testAgentUserBindingProposal = AgentUserBindingProposal.builder()
                .userIdentityToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
                .agentWorkloadToken("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...")
                .deviceFingerprint("dfp_abc123")
                .build();

        // Create test evidence per spec
        testEvidence = Evidence.builder()
                .sourcePromptCredential("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
                .build();

        // Create test operation proposal per spec - should be a Rego policy string
        testOperationProposal = AgentOperationProposal.builder()
                .policy("package agent\nallow { input.transaction.amount <= 50.0 }")
                .build();

        // Create test context per spec Figure 8
        OperationRequestContext.UserContext userContext = OperationRequestContext.UserContext.builder()
                .id("user_12345@myassistant.example")
                .build();

        OperationRequestContext.AgentContext agentContext = OperationRequestContext.AgentContext.builder()
                .instance("dfp_abc123")
                .platform("personal-agent.myassistant.example")
                .client("mobile-app-v1.myassistant.example")
                .build();

        testContext = OperationRequestContext.builder()
                .channel("mobile-app")
                .deviceFingerprint("dfp_abc123")
                .language("zh-CN")
                .user(userContext)
                .agent(agentContext)
                .build();
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should validate valid PAR-JWT successfully")
        void shouldValidateValidParJwtSuccessfully() throws JOSEException, ParseException {
            // Given
            String subject = "user_12345@myassistant.example";

            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getClaims()).isPresent();
            assertThat(result.getClaims().get().getSubject()).isEqualTo(subject);
            assertThat(result.getClaims().get().getEvidence()).isNotNull();
            assertThat(result.getClaims().get().getAgentUserBindingProposal()).isNotNull();
            assertThat(result.getClaims().get().getOperationProposal()).isNotNull();
            assertThat(result.getClaims().get().getContext()).isNotNull();
        }

        @Test
        @DisplayName("Should validate PAR-JWT with all required claims per spec Figure 1")
        void shouldValidateParJwtWithAllRequiredClaims() throws JOSEException, ParseException {
            // Given
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getClaims()).isPresent();

            // Verify all required JWT claims per spec
            ParJwtClaims claims = result.getClaims().get();
            assertThat(claims.getIssuer()).isEqualTo(issuer);
            assertThat(claims.getAudience()).hasSize(1).first().isEqualTo(audience);
            assertThat(claims.getSubject()).isEqualTo("user_12345@myassistant.example");
            assertThat(claims.getIssueTime()).isNotNull();
            assertThat(claims.getExpirationTime()).isNotNull();
            assertThat(claims.getJwtId()).isNotNull();

            // Verify all required custom claims per spec
            assertThat(claims.getEvidence()).isNotNull();
            assertThat(claims.getAgentUserBindingProposal()).isNotNull();
            assertThat(claims.getOperationProposal()).isNotNull();
            assertThat(claims.getContext()).isNotNull();
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Signature Verification")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should reject PAR-JWT with invalid signature")
        void shouldRejectParJwtWithInvalidSignature() throws JOSEException, ParseException {
            // Given
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // Tamper with the signature by replacing it with an invalid value
            // This ensures the signature verification will fail
            String[] jwtParts = parJwt.split("\\.");
            String tamperedSignature = "INVALID_SIGNATURE_THAT_WILL_FAIL_VERIFICATION";
            String tamperedJwt = jwtParts[0] + "." + jwtParts[1] + "." + tamperedSignature;

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(tamperedJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Invalid PAR-JWT signature");
        }

        @Test
        @DisplayName("Should reject PAR-JWT signed with wrong key")
        void shouldRejectParJwtSignedWithWrongKey() throws JOSEException, ParseException {
            // Given
            // Generate a different key pair
            RSAKeyGenerator keyGenerator = new RSAKeyGenerator(2048);
            RSAKey wrongSigningKey = keyGenerator.keyID("wrong-key").generate();
            AapParJwtGenerator wrongGenerator = new AapParJwtGenerator(wrongSigningKey, JWSAlgorithm.RS256, issuer, audience);

            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = wrongGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Invalid PAR-JWT signature");
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Expiration")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired PAR-JWT")
        void shouldRejectExpiredParJwt() throws JOSEException, ParseException {
            // Given: Create a JWT that expired 1 hour ago using low-level API
            String expiredParJwt = createExpiredParJwt();

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(expiredParJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("PAR-JWT has expired");
        }

        @Test
        @DisplayName("Should reject PAR-JWT without expiration time")
        void shouldRejectParJwtWithoutExpirationTime() throws JOSEException {
            // Given: Create a JWT without expiration time by directly building the claims
            String parJwtWithoutExp = createParJwtWithoutExpiration();

            // When
            AapParJwtValidator.ValidationResult result;
            result = aapParJwtValidator.validate(parJwtWithoutExp);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("expiration");
        }

        @Test
        @DisplayName("Should accept non-expired PAR-JWT")
        void shouldAcceptNonExpiredParJwt() throws JOSEException, ParseException {
            // Given
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Issuer")
    class IssuerTests {

        @Test
        @DisplayName("Should reject PAR-JWT with wrong issuer")
        void shouldRejectParJwtWithWrongIssuer() throws JOSEException, ParseException {
            // Given
            String wrongIssuer = "https://wrong-client.example.com";
            AapParJwtGenerator wrongGenerator = new AapParJwtGenerator(signingKey, JWSAlgorithm.RS256, wrongIssuer, audience);

            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = wrongGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Invalid issuer");
        }

        @Test
        @DisplayName("Should accept PAR-JWT with correct issuer")
        void shouldAcceptParJwtWithCorrectIssuer() throws JOSEException, ParseException {
            // Given
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Audience")
    class AudienceTests {

        @Test
        @DisplayName("Should reject PAR-JWT with wrong audience")
        void shouldRejectParJwtWithWrongAudience() throws JOSEException, ParseException {
            // Given
            String wrongAudience = "https://wrong-as.example.com";
            AapParJwtGenerator wrongGenerator = new AapParJwtGenerator(signingKey, JWSAlgorithm.RS256, issuer, wrongAudience);

            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = wrongGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Invalid audience");
        }

        @Test
        @DisplayName("Should accept PAR-JWT with correct audience")
        void shouldAcceptParJwtWithCorrectAudience() throws JOSEException, ParseException {
            // Given
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Required Claims")
    class RequiredClaimsTests {

        @Test
        @DisplayName("Should reject PAR-JWT missing evidence claim")
        void shouldRejectParJwtMissingEvidenceClaim() throws JOSEException {
            // Given: Create a JWT without evidence claim
            String parJwtWithoutEvidence = createParJwtWithoutClaim("evidence");

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwtWithoutEvidence);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Missing required claim: evidence");
        }

        @Test
        @DisplayName("Should reject PAR-JWT missing agent_user_binding_proposal claim")
        void shouldRejectParJwtMissingAgentUserBindingProposalClaim() throws JOSEException {
            // Given: Create a JWT without agent_user_binding_proposal claim
            String parJwtWithoutBindingProposal = createParJwtWithoutClaim("agent_user_binding_proposal");

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwtWithoutBindingProposal);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Missing required claim: agent_user_binding_proposal");
        }

        @Test
        @DisplayName("Should reject PAR-JWT missing agent_operation_proposal claim")
        void shouldRejectParJwtMissingAgentOperationProposalClaim() throws JOSEException {
            // Given: Create a JWT without agent_operation_proposal claim
            String parJwtWithoutOperationProposal = createParJwtWithoutClaim("agent_operation_proposal");

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwtWithoutOperationProposal);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Missing required claim: agent_operation_proposal");
        }

        @Test
        @DisplayName("Should reject PAR-JWT missing context claim")
        void shouldRejectParJwtMissingContextClaim() throws JOSEException {
            // Given: Create a JWT without context claim
            String parJwtWithoutContext = createParJwtWithoutClaim("context");

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwtWithoutContext);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Missing required claim: context");
        }

        @Test
        @DisplayName("Should validate PAR-JWT with all required claims")
        void shouldValidateParJwtWithAllRequiredClaims() throws JOSEException, ParseException {
            // Given
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(testAgentUserBindingProposal)
                    .evidence(testEvidence)
                    .operationProposal(testOperationProposal)
                    .context(testContext)
                    .expirationSeconds(3600)
                    .build();

            String parJwt = aapParJwtGenerator.generateParJwt(parameters);

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(parJwt);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getClaims()).isPresent();

            // Verify that all required claims are present
            ParJwtClaims claims = result.getClaims().get();
            assertThat(claims.getEvidence()).isNotNull();
            assertThat(claims.getAgentUserBindingProposal()).isNotNull();
            assertThat(claims.getOperationProposal()).isNotNull();
            assertThat(claims.getContext()).isNotNull();
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validation - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null PAR-JWT")
        void shouldRejectNullParJwt() {
            // Given
            String nullJwt = null;

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(nullJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("PAR-JWT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject empty PAR-JWT")
        void shouldRejectEmptyParJwt() {
            // Given
            String emptyJwt = "";

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(emptyJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("PAR-JWT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject PAR-JWT with only whitespace")
        void shouldRejectWhitespaceParJwt() {
            // Given
            String whitespaceJwt = "   ";

            // When
            AapParJwtValidator.ValidationResult result = aapParJwtValidator.validate(whitespaceJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("PAR-JWT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject malformed PAR-JWT")
        void shouldRejectMalformedParJwt() {
            // Given
            String malformedJwt = "not.a.jwt.at.all";

            // When
            AapParJwtValidator.ValidationResult result;
            result = aapParJwtValidator.validate(malformedJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).isPresent();
            assertThat(result.getErrorMessage().get()).contains("Error parsing PAR-JWT");
        }
    }

    @Nested
    @DisplayName("PAR-JWT Validator - Constructor Validation")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw exception when verificationKey is null")
        void shouldThrowExceptionWhenVerificationKeyIsNull() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new AapParJwtValidator(null, issuer, audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Verification key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when expectedIssuer is null")
        void shouldThrowExceptionWhenExpectedIssuerIsNull() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new AapParJwtValidator(verificationKey, null, audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expected issuer cannot be null or blank");
        }

        @Test
        @DisplayName("Should throw exception when expectedIssuer is empty")
        void shouldThrowExceptionWhenExpectedIssuerIsEmpty() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new AapParJwtValidator(verificationKey, "  ", audience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expected issuer cannot be null or blank");
        }

        @Test
        @DisplayName("Should throw exception when expectedAudience is null")
        void shouldThrowExceptionWhenExpectedAudienceIsNull() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new AapParJwtValidator(verificationKey, issuer, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expected audience cannot be null or blank");
        }

        @Test
        @DisplayName("Should throw exception when expectedAudience is empty")
        void shouldThrowExceptionWhenExpectedAudienceIsEmpty() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new AapParJwtValidator(verificationKey, issuer, "  "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expected audience cannot be null or blank");
        }
    }

    // Helper methods for creating test tokens with specific conditions
    private String createExpiredParJwt() throws JOSEException {
        // Create a JWT that expired 1 hour ago
        // Use low-level NimbusDS API to build a JWT with past expiration time
        long currentTimeSecs = System.currentTimeMillis() / 1000;
        long expiredTimeSecs = currentTimeSecs - 3600; // 1 hour ago

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("user_12345@myassistant.example")
                .issueTime(new java.util.Date(expiredTimeSecs * 1000))
                .expirationTime(new java.util.Date(expiredTimeSecs * 1000))
                .jwtID("test-jti-expired")
                .claim("evidence", Map.of("sourcePromptCredential", "test-credential"))
                .claim("agent_user_binding_proposal", Map.of(
                    "user_identity_token", "test-token",
                    "agent_workload_token", "test-token"
                ))
                .claim("agent_operation_proposal", "package agent\nallow { true }")
                .claim("context", Map.of("channel", "test-channel"));

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("JWT"))
                        .build(),
                claimsBuilder.build()
        );

        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String createParJwtWithoutExpiration() throws JOSEException {
        // Create a JWT with all required claims except expiration
        // Use low-level NimbusDS API to build a JWT without exp claim
        long currentTimeSecs = System.currentTimeMillis() / 1000;

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("user_12345@myassistant.example")
                .issueTime(new java.util.Date(currentTimeSecs * 1000))
                .jwtID("test-jti-no-exp")
                .claim("evidence", Map.of("sourcePromptCredential", "test-credential"))
                .claim("agent_user_binding_proposal", Map.of(
                    "user_identity_token", "test-token",
                    "agent_workload_token", "test-token"
                ))
                .claim("agent_operation_proposal", "package agent\nallow { true }")
                .claim("context", Map.of("channel", "test-channel"));

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("JWT"))
                        .build(),
                claimsBuilder.build()
        );

        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }

    private String createParJwtWithoutClaim(String claimToRemove) throws JOSEException {
        // Create a JWT with all claims except the specified one using low-level API
        long currentTimeSecs = System.currentTimeMillis() / 1000;
        long expirationTimeSecs = currentTimeSecs + 3600;

        // Build claims set without the specified claim
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject("user_12345@myassistant.example")
                .issueTime(new java.util.Date(currentTimeSecs * 1000))
                .expirationTime(new java.util.Date(expirationTimeSecs * 1000))
                .jwtID("test-jti-" + claimToRemove);

        // Add claims conditionally based on which claim to remove
        if (!"evidence".equals(claimToRemove)) {
            claimsBuilder.claim("evidence", Map.of("sourcePromptCredential", "test-credential"));
        }
        if (!"agent_user_binding_proposal".equals(claimToRemove)) {
            claimsBuilder.claim("agent_user_binding_proposal", Map.of(
                "user_identity_token", "test-token",
                "agent_workload_token", "test-token"
            ));
        }
        if (!"agent_operation_proposal".equals(claimToRemove)) {
            claimsBuilder.claim("agent_operation_proposal", "package agent\nallow { true }");
        }
        if (!"context".equals(claimToRemove)) {
            claimsBuilder.claim("context", Map.of("channel", "test-channel"));
        }

        // Build and sign JWT
        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .type(new JOSEObjectType("JWT"))
                        .build(),
                claimsBuilder.build()
        );

        signedJwt.sign(new RSASSASigner(signingKey));
        return signedJwt.serialize();
    }
}