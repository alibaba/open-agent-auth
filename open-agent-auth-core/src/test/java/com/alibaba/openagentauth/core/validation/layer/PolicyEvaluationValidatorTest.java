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

import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link PolicyEvaluationValidator}.
 * <p>
 * Tests the Layer 5 validator for policy evaluation and authorization decision.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyEvaluationValidator Tests")
class PolicyEvaluationValidatorTest {

    @Mock
    private PolicyEvaluator mockPolicyEvaluator;

    private PolicyEvaluationValidator validator;

    @BeforeEach
    void setUp() {
        validator = new PolicyEvaluationValidator(mockPolicyEvaluator);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when PolicyEvaluator is null")
        void shouldThrowExceptionWhenPolicyEvaluatorIsNull() {
            assertThatThrownBy(() -> new PolicyEvaluationValidator(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("PolicyEvaluator");
        }

        @Test
        @DisplayName("Should create validator successfully")
        void shouldCreateValidatorSuccessfully() {
            PolicyEvaluationValidator validator = new PolicyEvaluationValidator(mockPolicyEvaluator);
            assertThat(validator).isNotNull();
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should throw NullPointerException when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            assertThatThrownBy(() -> validator.validate(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("context");
        }

        @Test
        @DisplayName("Should return failure when AOAT is null")
        void shouldReturnFailureWhenAoatIsNull() {
            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(null)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("AOAT is required for policy evaluation");
        }

        @Test
        @DisplayName("Should return failure when AOAT authorization is null")
        void shouldReturnFailureWhenAoatAuthorizationIsNull() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            when(aoat.getAuthorization()).thenReturn(null);

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("AOAT is missing policy ID in agent_operation_authorization");
            assertThat(result.getMetadata()).isEqualTo("Layer 5 Policy Evaluation");
        }

        @Test
        @DisplayName("Should return failure when policy ID is null")
        void shouldReturnFailureWhenPolicyIdIsNull() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);
            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn(null);

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("AOAT is missing policy ID in agent_operation_authorization");
            assertThat(result.getMetadata()).isEqualTo("Layer 5 Policy Evaluation");
        }

        @Test
        @DisplayName("Should return failure when policy ID is empty")
        void shouldReturnFailureWhenPolicyIdIsEmpty() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);
            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn("");

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("AOAT is missing policy ID in agent_operation_authorization");
            assertThat(result.getMetadata()).isEqualTo("Layer 5 Policy Evaluation");
        }

        @Test
        @DisplayName("Should return success when policy evaluation allows")
        void shouldReturnSuccessWhenPolicyEvaluationAllows() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);
            AgentIdentity agentIdentity = mock(AgentIdentity.class);

            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn("policy-123");
            when(aoat.getSubject()).thenReturn("user-123");
            when(aoat.getIssuer()).thenReturn("https://issuer.example.com");
            when(aoat.getAgentIdentity()).thenReturn(agentIdentity);
            when(agentIdentity.getId()).thenReturn("agent-123");
            when(agentIdentity.getIssuer()).thenReturn("https://agent-issuer.example.com");
            when(agentIdentity.getIssuedTo()).thenReturn("https://issued-to.example.com");

            PolicyEvaluationResult evaluationResult = new PolicyEvaluationResult(true, "Operation allowed", null, null);
            when(mockPolicyEvaluator.evaluateWithDetails(anyString(), any())).thenReturn(evaluationResult);

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .httpMethod("POST")
                    .httpUri("/api/resource")
                    .httpHeaders(Map.of("Content-Type", "application/json"))
                    .httpBody("{}")
                    .requestTimestamp(Date.from(Instant.now()))
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getMetadata()).isEqualTo("Layer 5: Policy evaluation completed successfully - operation allowed");
            verify(mockPolicyEvaluator, times(1)).evaluateWithDetails(eq("policy-123"), any());
        }

        @Test
        @DisplayName("Should return failure when policy evaluation denies")
        void shouldReturnFailureWhenPolicyEvaluationDenies() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);
            AgentIdentity agentIdentity = mock(AgentIdentity.class);

            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn("policy-123");
            when(aoat.getSubject()).thenReturn("user-123");
            when(aoat.getIssuer()).thenReturn("https://issuer.example.com");
            when(aoat.getAgentIdentity()).thenReturn(agentIdentity);
            when(agentIdentity.getId()).thenReturn("agent-123");
            when(agentIdentity.getIssuer()).thenReturn("https://agent-issuer.example.com");
            when(agentIdentity.getIssuedTo()).thenReturn("https://issued-to.example.com");

            PolicyEvaluationResult evaluationResult = new PolicyEvaluationResult(false, "Operation denied: insufficient permissions", null, null);
            when(mockPolicyEvaluator.evaluateWithDetails(anyString(), any())).thenReturn(evaluationResult);

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .httpMethod("POST")
                    .httpUri("/api/resource")
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("Operation denied by policy: Operation denied: insufficient permissions");
            assertThat(result.getMetadata()).isEqualTo("Layer 5 Policy Evaluation");
        }

        @Test
        @DisplayName("Should return failure when policy evaluator throws exception")
        void shouldReturnFailureWhenPolicyEvaluatorThrowsException() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);
            AgentIdentity agentIdentity = mock(AgentIdentity.class);

            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn("policy-123");
            when(aoat.getSubject()).thenReturn("user-123");
            when(aoat.getIssuer()).thenReturn("https://issuer.example.com");
            when(aoat.getAgentIdentity()).thenReturn(agentIdentity);
            when(agentIdentity.getId()).thenReturn("agent-123");
            when(agentIdentity.getIssuer()).thenReturn("https://agent-issuer.example.com");
            when(agentIdentity.getIssuedTo()).thenReturn("https://issued-to.example.com");

            when(mockPolicyEvaluator.evaluateWithDetails(anyString(), any()))
                    .thenThrow(new RuntimeException("Policy evaluation error"));

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isFailure()).isTrue();
            assertThat(result.getErrors()).contains("Policy evaluation failed: Policy evaluation error");
            assertThat(result.getMetadata()).isEqualTo("Layer 5 Policy Evaluation");
        }

        @Test
        @DisplayName("Should build evaluation input with all fields")
        void shouldBuildEvaluationInputWithAllFields() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);
            AgentIdentity agentIdentity = mock(AgentIdentity.class);

            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn("policy-123");
            when(aoat.getSubject()).thenReturn("user-123");
            when(aoat.getIssuer()).thenReturn("https://issuer.example.com");
            when(aoat.getAgentIdentity()).thenReturn(agentIdentity);
            when(agentIdentity.getId()).thenReturn("agent-123");
            when(agentIdentity.getIssuer()).thenReturn("https://agent-issuer.example.com");
            when(agentIdentity.getIssuedTo()).thenReturn("https://issued-to.example.com");

            PolicyEvaluationResult evaluationResult = new PolicyEvaluationResult(true, "Allowed", null, null);
            when(mockPolicyEvaluator.evaluateWithDetails(anyString(), any())).thenReturn(evaluationResult);

            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Authorization", "Bearer token");

            Map<String, Object> attributes = new HashMap<>();
            attributes.put("custom-key", "custom-value");

            Date timestamp = Date.from(Instant.now());

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .httpMethod("POST")
                    .httpUri("/api/resource")
                    .httpHeaders(headers)
                    .httpBody("{\"key\":\"value\"}")
                    .requestTimestamp(timestamp)
                    .attributes(attributes)
                    .build();

            validator.validate(context);

            verify(mockPolicyEvaluator, times(1)).evaluateWithDetails(eq("policy-123"), argThat(input -> {
                assertThat(input).isNotNull();
                assertThat(input).containsKey("user");
                assertThat(input).containsKey("agent");
                assertThat(input).containsKey("request");
                assertThat(input).containsKey("timestamp");
                assertThat(input).containsKey("custom-key");
                
                @SuppressWarnings("unchecked")
                Map<String, String> user = (Map<String, String>) input.get("user");
                assertThat(user.get("id")).isEqualTo("user-123");
                assertThat(user.get("issuer")).isEqualTo("https://issuer.example.com");
                
                @SuppressWarnings("unchecked")
                Map<String, String> agent = (Map<String, String>) input.get("agent");
                assertThat(agent.get("id")).isEqualTo("agent-123");
                assertThat(agent.get("issuer")).isEqualTo("https://agent-issuer.example.com");
                assertThat(agent.get("issuedTo")).isEqualTo("https://issued-to.example.com");
                
                @SuppressWarnings("unchecked")
                Map<String, Object> request = (Map<String, Object>) input.get("request");
                assertThat(request.get("method")).isEqualTo("POST");
                assertThat(request.get("uri")).isEqualTo("/api/resource");
                assertThat(request.get("headers")).isEqualTo(headers);
                assertThat(request.get("body")).isEqualTo("{\"key\":\"value\"}");
                
                assertThat(input.get("custom-key")).isEqualTo("custom-value");
                
                return true;
            }));
        }

        @Test
        @DisplayName("Should handle null agent identity")
        void shouldHandleNullAgentIdentity() {
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            AgentOperationAuthorization authorization = mock(AgentOperationAuthorization.class);

            when(aoat.getAuthorization()).thenReturn(authorization);
            when(authorization.getPolicyId()).thenReturn("policy-123");
            when(aoat.getSubject()).thenReturn("user-123");
            when(aoat.getIssuer()).thenReturn("https://issuer.example.com");
            when(aoat.getAgentIdentity()).thenReturn(null);

            PolicyEvaluationResult evaluationResult = new PolicyEvaluationResult(true, "Allowed", null, null);
            when(mockPolicyEvaluator.evaluateWithDetails(anyString(), any())).thenReturn(evaluationResult);

            ValidationContext context = ValidationContext.builder()
                    .agentOaToken(aoat)
                    .build();

            LayerValidationResult result = validator.validate(context);

            assertThat(result.isSuccess()).isTrue();
            verify(mockPolicyEvaluator, times(1)).evaluateWithDetails(eq("policy-123"), argThat(input -> {
                assertThat(input).containsKey("user");
                assertThat(input).doesNotContainKey("agent");
                return true;
            }));
        }
    }

    @Nested
    @DisplayName("Metadata Tests")
    class MetadataTests {

        @Test
        @DisplayName("Should return correct validator name")
        void shouldReturnCorrectValidatorName() {
            assertThat(validator.getName()).isEqualTo("Layer 5: Policy Evaluation Validator");
        }

        @Test
        @DisplayName("Should return correct order")
        void shouldReturnCorrectOrder() {
            assertThat(validator.getOrder()).isEqualTo(5.0);
        }
    }
}
