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
package com.alibaba.openagentauth.core.validation.layer;

import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OperationAuthorizationValidator}.
 * <p>
 * This test class validates the Layer 3 validator for Agent Operation Authorization Token (AOAT)
 * verification, covering normal flow, exception flow, and delegation chain validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OperationAuthorizationValidator Tests")
@ExtendWith(MockitoExtension.class)
class OperationAuthorizationValidatorTest {

    @Mock
    private AoatValidator aoatValidator;

    @Mock
    private AgentOperationAuthToken mockAoat;

    private OperationAuthorizationValidator validator;

    private static final String VALID_AOAT_JWT = "valid.aoat.jwt.string";
    private static final String INVALID_AOAT_JWT = "invalid.aoat.jwt.string";

    @BeforeEach
    void setUp() {
        validator = new OperationAuthorizationValidator(aoatValidator);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create validator with valid AoatValidator")
        void shouldCreateValidatorWithValidAoatValidator() {
            OperationAuthorizationValidator v = new OperationAuthorizationValidator(aoatValidator);
            
            assertThat(v).isNotNull();
            assertThat(v.getName()).isEqualTo("Layer 3: Agent Operation Authorization Validator");
            assertThat(v.getOrder()).isEqualTo(3.0);
        }

        @Test
        @DisplayName("Should throw exception when AoatValidator is null")
        void shouldThrowExceptionWhenAoatValidatorIsNull() {
            assertThatThrownBy(() -> new OperationAuthorizationValidator(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AoatValidator");
        }
    }

    @Nested
    @DisplayName("Validation Tests - Missing AOAT")
    class ValidationTestsMissingAoat {

        @Test
        @DisplayName("Should return failure when AOAT is null")
        void shouldReturnFailureWhenAoatIsNull() {
            ValidationContext context = ValidationContext.builder()
                .agentOaToken(null)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("AOAT is required");
        }

        @Test
        @DisplayName("Should return failure when AOAT JWT string is null")
        void shouldReturnFailureWhenAoatJwtStringIsNull() throws JOSEException {
            when(mockAoat.getJwtString()).thenReturn(null);

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("AOAT JWT string is required");
        }

        @Test
        @DisplayName("Should return failure when AOAT JWT string is empty")
        void shouldReturnFailureWhenAoatJwtStringIsEmpty() throws JOSEException {
            when(mockAoat.getJwtString()).thenReturn("");

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("AOAT JWT string is required");
        }

        @Test
        @DisplayName("Should return failure when getting JWT string throws JOSEException")
        void shouldReturnFailureWhenGettingJwtStringThrowsJoseException() throws JOSEException {
            when(mockAoat.getJwtString()).thenThrow(new JOSEException("Test exception"));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("AOAT JWT string is not available");
            assertThat(result.getErrors().get(0)).contains("Test exception");
        }
    }

    @Nested
    @DisplayName("Validation Tests - AOAT Validation Failure")
    class ValidationTestsAoatValidationFailure {

        @Test
        @DisplayName("Should return failure when AoatValidator returns invalid result")
        void shouldReturnFailureWhenAoatValidatorReturnsInvalidResult() throws JOSEException, ParseException {
            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.failure("Token expired"));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("Token expired");
        }

        @Test
        @DisplayName("Should return failure when AoatValidator throws exception")
        void shouldReturnFailureWhenAoatValidatorThrowsException() throws JOSEException, ParseException {
            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(aoatValidator.validate(anyString()))
                .thenThrow(new RuntimeException("Validation error"));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("Validation error");
        }
    }

    @Nested
    @DisplayName("Validation Tests - Successful Validation")
    class ValidationTestsSuccessfulValidation {

        @Test
        @DisplayName("Should return success when AOAT is valid without delegation chain")
        void shouldReturnSuccessWhenAoatIsValidWithoutDelegationChain() throws JOSEException, ParseException {
            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(Collections.emptyList());
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getMetadata()).contains("Layer 3: AOAT validation completed successfully");
        }

        @Test
        @DisplayName("Should return success when AOAT is valid with null delegation chain")
        void shouldReturnSuccessWhenAoatIsValidWithNullDelegationChain() throws JOSEException, ParseException {
            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(null);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
        }
    }

    @Nested
    @DisplayName("Delegation Chain Validation Tests")
    class DelegationChainValidationTests {

        @Test
        @DisplayName("Should validate successful delegation chain")
        void shouldValidateSuccessfulDelegationChain() throws JOSEException, ParseException {
            AgentIdentity delegatorIdentity = AgentIdentity.builder()
                .id("agent_001")
                .build();

            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(delegatorIdentity)
                .delegationTimestamp(Instant.now().minusSeconds(3600))
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should return failure when delegation record is missing delegator_jti")
        void shouldReturnFailureWhenDelegationRecordIsMissingDelegatorJti() throws JOSEException, ParseException {
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti(null)
                .delegatorAgentIdentity(AgentIdentity.builder().id("agent_001").build())
                .delegationTimestamp(Instant.now())
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("delegator_jti");
        }

        @Test
        @DisplayName("Should return failure when delegation record is missing delegator_agent_identity")
        void shouldReturnFailureWhenDelegationRecordIsMissingDelegatorAgentIdentity() throws JOSEException, ParseException {
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(null)
                .delegationTimestamp(Instant.now())
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("delegator_agent_identity");
        }

        @Test
        @DisplayName("Should return failure when delegator_agent_identity is missing id")
        void shouldReturnFailureWhenDelegatorAgentIdentityIsMissingId() throws JOSEException, ParseException {
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(AgentIdentity.builder().id(null).build())
                .delegationTimestamp(Instant.now())
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("delegator_agent_identity");
        }

        @Test
        @DisplayName("Should return failure when delegation record is missing delegation_timestamp")
        void shouldReturnFailureWhenDelegationRecordIsMissingDelegationTimestamp() throws JOSEException, ParseException {
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(AgentIdentity.builder().id("agent_001").build())
                .delegationTimestamp(null)
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("delegation_timestamp");
        }

        @Test
        @DisplayName("Should return failure when delegation_timestamp is in the future")
        void shouldReturnFailureWhenDelegationTimestampIsInTheFuture() throws JOSEException, ParseException {
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(AgentIdentity.builder().id("agent_001").build())
                .delegationTimestamp(Instant.now().plusSeconds(3600))
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("delegation_timestamp");
            assertThat(result.getErrors().get(0)).contains("future");
        }

        @Test
        @DisplayName("Should return failure when delegation record is missing as_signature")
        void shouldReturnFailureWhenDelegationRecordIsMissingAsSignature() throws JOSEException, ParseException {
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(AgentIdentity.builder().id("agent_001").build())
                .delegationTimestamp(Instant.now())
                .asSignature(null)
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).isNotEmpty();
            assertThat(result.getErrors().get(0)).contains("as_signature");
        }

        @Test
        @DisplayName("Should validate multiple delegation records")
        void shouldValidateMultipleDelegationRecords() throws JOSEException, ParseException {
            AgentIdentity identity1 = AgentIdentity.builder().id("agent_001").build();
            AgentIdentity identity2 = AgentIdentity.builder().id("agent_002").build();

            DelegationChain record1 = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(identity1)
                .delegationTimestamp(Instant.now().minusSeconds(7200))
                .asSignature("signature_001")
                .build();

            DelegationChain record2 = DelegationChain.builder()
                .delegatorJti("jti_002")
                .delegatorAgentIdentity(identity2)
                .delegationTimestamp(Instant.now().minusSeconds(3600))
                .asSignature("signature_002")
                .build();

            List<DelegationChain> delegationChain = List.of(record1, record2);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty delegation chain")
        void shouldHandleEmptyDelegationChain() throws JOSEException, ParseException {
            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(Collections.emptyList());
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should handle delegation timestamp exactly at current time")
        void shouldHandleDelegationTimestampExactlyAtCurrentTime() throws JOSEException, ParseException {
            Instant now = Instant.now();
            
            DelegationChain delegationRecord = DelegationChain.builder()
                .delegatorJti("jti_001")
                .delegatorAgentIdentity(AgentIdentity.builder().id("agent_001").build())
                .delegationTimestamp(now)
                .asSignature("signature_001")
                .build();

            List<DelegationChain> delegationChain = List.of(delegationRecord);

            when(mockAoat.getJwtString()).thenReturn(VALID_AOAT_JWT);
            when(mockAoat.getDelegationChain()).thenReturn(delegationChain);
            when(aoatValidator.validate(anyString()))
                .thenReturn(TokenValidationResult.success(mockAoat));

            ValidationContext context = ValidationContext.builder()
                .agentOaToken(mockAoat)
                .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
        }
    }
}
