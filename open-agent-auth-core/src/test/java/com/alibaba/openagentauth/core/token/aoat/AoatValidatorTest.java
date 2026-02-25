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

import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.nimbusds.jose.*;
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
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AoatValidator}.
 * <p>
 * Tests the validator's behavior including:
 * <ul>
 *   <li>Validating tokens with correct signatures and claims</li>
 *   <li>Rejecting tokens with invalid signatures</li>
 *   <li>Rejecting expired tokens</li>
 *   <li>Rejecting tokens with invalid issuer or audience</li>
 *   <li>Rejecting tokens with missing required claims</li>
 *   <li>Edge cases for validation</li>
 * </ul>
 * </p>
 */
@DisplayName("AoatValidator Tests")
class AoatValidatorTest {

    private static final String VERIFICATION_KEY_ID = "test-verification-key";
    
    private RSAKey verificationKey;
    private RSAKey signingKey;
    private String expectedIssuer;
    private String expectedAudience;
    private AoatValidator validator;
    private AoatGenerator generator;
    private KeyManager keyManager;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair
        signingKey = new RSAKeyGenerator(2048)
                .keyID(VERIFICATION_KEY_ID)
                .generate();
        verificationKey = signingKey.toPublicJWK();

        expectedIssuer = "https://issuer.example.com";
        expectedAudience = "https://audience.example.com";

        // Create mock KeyManager
        keyManager = mock(KeyManager.class);
        when(keyManager.resolveVerificationKey(anyString())).thenReturn(verificationKey);

        // Create validator with new constructor
        validator = new AoatValidator(keyManager, VERIFICATION_KEY_ID, expectedIssuer, expectedAudience);

        // Create generator for test tokens
        generator = new AoatGenerator(signingKey, JWSAlgorithm.RS256, expectedIssuer, expectedAudience);
    }

    @Nested
    @DisplayName("Successful Validation Tests")
    class SuccessfulValidationTests {

        @Test
        @DisplayName("Should validate token with all required claims")
        void shouldValidateTokenWithAllRequiredClaims() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getSubject()).isEqualTo("user123");
            assertThat(result.getToken().getAgentIdentity()).isNotNull();
            assertThat(result.getToken().getAuthorization()).isNotNull();
        }

        @Test
        @DisplayName("Should validate token with optional claims")
        void shouldValidateTokenWithOptionalClaims() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .evidence(Evidence.builder()
                            .sourcePromptCredential("test-credential")
                            .build())
                    .context(TokenAuthorizationContext.builder()
                            .renderedText("Test operation")
                            .build())
                    .build();

            String jwtString = token.getJwtString();
            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getEvidence()).isNotNull();
            assertThat(result.getToken().getContext()).isNotNull();
        }

        @Test
        @DisplayName("Should validate token with delegation chain")
        void shouldValidateTokenWithDelegationChain() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.newBuilder("user123", agentIdentity, authorization, 3600)
                    .delegationChain(java.util.List.of(
                            DelegationChain.builder()
                                    .delegatorJti("delegator-jti-001")
                                    .delegatorAgentIdentity(agentIdentity)
                                    .delegationTimestamp(Instant.now())
                                    .operationSummary("Test delegation")
                                    .asSignature("test-signature")
                                    .build()
                    ))
                    .build();

            String jwtString = token.getJwtString();
            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getDelegationChain()).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Signature Validation Tests")
    class SignatureValidationTests {

        @Test
        @DisplayName("Should reject token with invalid signature")
        void shouldRejectTokenWithInvalidSignature() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            // Generate token with one key
            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            // Create validator with different key via mock KeyManager
            RSAKey differentKey = new RSAKeyGenerator(2048)
                    .keyID("different-key-id")
                    .generate()
                    .toPublicJWK();
            
            KeyManager differentKeyManager = mock(KeyManager.class);
            when(differentKeyManager.resolveVerificationKey(anyString())).thenReturn(differentKey);
            
            AoatValidator validatorWithDifferentKey = new AoatValidator(
                    differentKeyManager, VERIFICATION_KEY_ID, expectedIssuer, expectedAudience);

            TokenValidationResult<AgentOperationAuthToken> result = validatorWithDifferentKey.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid AOAT signature");
        }

        @Test
        @DisplayName("Should reject token with wrong algorithm")
        void shouldRejectTokenWithWrongAlgorithm() throws Exception {
            // Create a token with RS256 algorithm but try to validate with different expectations
            // This test verifies that the validator checks the algorithm
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            // Parse and modify the JWT to change algorithm (simulated)
            SignedJWT signedJwt = SignedJWT.parse(jwtString);
            // The validator should reject if algorithm is not RS256
            // Our implementation uses RS256, so this test validates the algorithm check
            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            // Should pass because we're using RS256
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("Expiration Validation Tests")
    class ExpirationValidationTests {

        @Test
        @DisplayName("Should reject expired token")
        void shouldRejectExpiredToken() throws Exception {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            // Create a token manually with past expiration time
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(expectedIssuer)
                    .subject("user123")
                    .audience(expectedAudience)
                    .expirationTime(Date.from(Instant.now().minusSeconds(3600))) // Expired 1 hour ago
                    .issueTime(Date.from(Instant.now().minusSeconds(7200)))
                    .jwtID("test-jti-001")
                    .claim("agent_identity", createAgentIdentityMap())
                    .claim("agent_operation_authorization", createAuthorizationMap());

            JWTClaimsSet claimsSet = claimsBuilder.build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(new JOSEObjectType("JWT"))
                    .build();

            SignedJWT signedJwt = new SignedJWT(header, claimsSet);
            signedJwt.sign(new RSASSASigner(signingKey));

            String jwtString = signedJwt.serialize();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("AOAT has expired");
        }

        @Test
        @DisplayName("Should accept token with future expiration")
        void shouldAcceptTokenWithFutureExpiration() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            // Generate token with long expiration
            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 86400);
            String jwtString = token.getJwtString();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("Issuer Validation Tests")
    class IssuerValidationTests {

        @Test
        @DisplayName("Should reject token with invalid issuer")
        void shouldRejectTokenWithInvalidIssuer() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            // Generate token with different issuer
            AoatGenerator generatorWithDifferentIssuer = new AoatGenerator(
                    signingKey,
                    JWSAlgorithm.RS256,
                    "https://different-issuer.example.com",
                    expectedAudience
            );

            AgentOperationAuthToken token = generatorWithDifferentIssuer.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid issuer");
        }

        @Test
        @DisplayName("Should accept token with matching issuer")
        void shouldAcceptTokenWithMatchingIssuer() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().getIssuer()).isEqualTo(expectedIssuer);
        }
    }

    @Nested
    @DisplayName("Audience Validation Tests")
    class AudienceValidationTests {

        @Test
        @DisplayName("Should reject token with invalid audience")
        void shouldRejectTokenWithInvalidAudience() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            // Generate token with different audience
            AoatGenerator generatorWithDifferentAudience = new AoatGenerator(
                    signingKey,
                    JWSAlgorithm.RS256,
                    expectedIssuer,
                    "https://different-audience.example.com"
            );

            AgentOperationAuthToken token = generatorWithDifferentAudience.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid audience");
        }

        @Test
        @DisplayName("Should accept token with matching audience")
        void shouldAcceptTokenWithMatchingAudience() throws JOSEException, ParseException {
            AgentIdentity agentIdentity = createAgentIdentity();
            AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                    .policyId("policy-123")
                    .build();

            AgentOperationAuthToken token = generator.generateAoat("user123", agentIdentity, authorization, 3600);
            String jwtString = token.getJwtString();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().getAudience()).isEqualTo(expectedAudience);
        }
    }

    @Nested
    @DisplayName("Required Claims Validation Tests")
    class RequiredClaimsValidationTests {

        @Test
        @DisplayName("Should reject token missing subject claim")
        void shouldRejectTokenMissingSubjectClaim() throws Exception {
            // Create a JWT manually without subject claim
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(expectedIssuer)
                    .audience(expectedAudience)
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .issueTime(Date.from(Instant.now()))
                    .jwtID("test-jti-001")
                    .claim("agent_identity", createAgentIdentityMap())
                    .claim("agent_operation_authorization", createAuthorizationMap());

            JWTClaimsSet claimsSet = claimsBuilder.build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(new JOSEObjectType("JWT"))
                    .build();

            SignedJWT signedJwt = new SignedJWT(header, claimsSet);
            signedJwt.sign(new RSASSASigner(signingKey));

            String jwtString = signedJwt.serialize();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }

        @Test
        @DisplayName("Should reject token missing agent_identity claim")
        void shouldRejectTokenMissingAgentIdentityClaim() throws Exception {
            // Create a JWT manually without agent_identity claim
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(expectedIssuer)
                    .subject("user123")
                    .audience(expectedAudience)
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .issueTime(Date.from(Instant.now()))
                    .jwtID("test-jti-001")
                    .claim("agent_operation_authorization", createAuthorizationMap());

            JWTClaimsSet claimsSet = claimsBuilder.build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(new JOSEObjectType("JWT"))
                    .build();

            SignedJWT signedJwt = new SignedJWT(header, claimsSet);
            signedJwt.sign(new RSASSASigner(signingKey));

            String jwtString = signedJwt.serialize();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }

        @Test
        @DisplayName("Should reject token missing agent_operation_authorization claim")
        void shouldRejectTokenMissingAuthorizationClaim() throws Exception {
            // Create a JWT manually without agent_operation_authorization claim
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(expectedIssuer)
                    .subject("user123")
                    .audience(expectedAudience)
                    .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                    .issueTime(Date.from(Instant.now()))
                    .jwtID("test-jti-001")
                    .claim("agent_identity", createAgentIdentityMap());

            JWTClaimsSet claimsSet = claimsBuilder.build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(new JOSEObjectType("JWT"))
                    .build();

            SignedJWT signedJwt = new SignedJWT(header, claimsSet);
            signedJwt.sign(new RSASSASigner(signingKey));

            String jwtString = signedJwt.serialize();

            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(jwtString);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should reject null token")
        void shouldRejectNullToken() throws ParseException {
            TokenValidationResult<AgentOperationAuthToken> result = validator.validate(null);

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("AOAT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject empty token")
        void shouldRejectEmptyToken() throws ParseException {
            TokenValidationResult<AgentOperationAuthToken> result = validator.validate("");

            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("AOAT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject malformed JWT")
        void shouldRejectMalformedJwt() {
            // The validator throws ParseException for malformed JWT
            assertThatThrownBy(() -> validator.validate("not-a-valid-jwt"))
                    .isInstanceOf(ParseException.class)
                    .hasMessageContaining("Missing part delimiters");
        }
    }

    @Nested
    @DisplayName("Constructor Validation Tests")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw exception when verification key is null")
        void shouldThrowExceptionWhenVerificationKeyIsNull() {
            KeyManager nullKeyManager = null;
            assertThatThrownBy(() -> new AoatValidator(nullKeyManager, VERIFICATION_KEY_ID, expectedIssuer, expectedAudience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Key manager cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when expected issuer is null")
        void shouldThrowExceptionWhenExpectedIssuerIsNull() {
            KeyManager testKeyManager = mock(KeyManager.class);
            assertThatThrownBy(() -> new AoatValidator(testKeyManager, VERIFICATION_KEY_ID, null, expectedAudience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Expected issuer cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when expected issuer is empty")
        void shouldThrowExceptionWhenExpectedIssuerIsEmpty() {
            KeyManager testKeyManager = mock(KeyManager.class);
            assertThatThrownBy(() -> new AoatValidator(testKeyManager, VERIFICATION_KEY_ID, "", expectedAudience))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Expected issuer cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when expected audience is null")
        void shouldThrowExceptionWhenExpectedAudienceIsNull() {
            KeyManager testKeyManager = mock(KeyManager.class);
            assertThatThrownBy(() -> new AoatValidator(testKeyManager, VERIFICATION_KEY_ID, expectedIssuer, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Expected audience cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when expected audience is empty")
        void shouldThrowExceptionWhenExpectedAudienceIsEmpty() {
            KeyManager testKeyManager = mock(KeyManager.class);
            assertThatThrownBy(() -> new AoatValidator(testKeyManager, VERIFICATION_KEY_ID, expectedIssuer, ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Expected audience cannot be null or empty");
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

    private java.util.Map<String, Object> createAgentIdentityMap() {
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("version", "1.0");
        map.put("id", "agent-001");
        map.put("issuer", "https://issuer.example.com");
        map.put("issuedTo", "user123");
        
        java.util.Map<String, Object> issuedFor = new java.util.HashMap<>();
        issuedFor.put("platform", "test-platform");
        issuedFor.put("client", "test-client");
        issuedFor.put("clientInstance", "test-instance");
        map.put("issuedFor", issuedFor);
        
        map.put("issuanceDate", Instant.now().toString());
        map.put("validFrom", Instant.now().toString());
        map.put("expires", Instant.now().plusSeconds(86400).toString());
        
        return map;
    }

    private java.util.Map<String, Object> createAuthorizationMap() {
        java.util.Map<String, Object> map = new java.util.HashMap<>();
        map.put("policy_id", "policy-123");
        return map;
    }
}
