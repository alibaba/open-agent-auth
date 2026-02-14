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
package com.alibaba.openagentauth.core.model.oauth2.par;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AapParParameters.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * AapParParameters, including normal construction, method chaining,
 * required field validation, optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("AapParParameters.Builder Tests")
class AapParParametersTest {

    private static final long EXPIRATION_SECONDS = 3600;
    private static final String USER_ID = "user_12345";
    private static final String CLIENT_ID = "client_abc";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String STATE = "xyz789";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build parameters with all required fields")
        void shouldBuildParametersWithAllRequiredFields() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build();

            // Then
            assertThat(parameters).isNotNull();
            assertThat(parameters.getAgentUserBindingProposal()).isEqualTo(bindingProposal);
            assertThat(parameters.getEvidence()).isEqualTo(evidence);
            assertThat(parameters.getOperationProposal()).isEqualTo(operationProposal);
            assertThat(parameters.getContext()).isEqualTo(context);
            assertThat(parameters.getExpirationSeconds()).isEqualTo(EXPIRATION_SECONDS);
        }

        @Test
        @DisplayName("Should build parameters with all fields including optional")
        void shouldBuildParametersWithAllFieldsIncludingOptional() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .userId(USER_ID)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .state(STATE)
                    .build();

            // Then
            assertThat(parameters).isNotNull();
            assertThat(parameters.getUserId()).isEqualTo(USER_ID);
            assertThat(parameters.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(parameters.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(parameters.getState()).isEqualTo(STATE);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .userId(USER_ID)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .state(STATE)
                    .build();

            // Then
            assertThat(parameters).isNotNull();
            assertThat(parameters.getUserId()).isEqualTo(USER_ID);
            assertThat(parameters.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(parameters.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(parameters.getState()).isEqualTo(STATE);
        }
    }

    @Nested
    @DisplayName("Required Field Validation Tests")
    class RequiredFieldValidationTests {

        @Test
        @DisplayName("Should throw exception when agentUserBindingProposal is null")
        void shouldThrowExceptionWhenAgentUserBindingProposalIsNull() {
            // Given
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When & Then
            assertThatThrownBy(() -> AapParParameters.builder()
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent user binding proposal");
        }

        @Test
        @DisplayName("Should throw exception when evidence is null")
        void shouldThrowExceptionWhenEvidenceIsNull() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When & Then
            assertThatThrownBy(() -> AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Evidence");
        }

        @Test
        @DisplayName("Should throw exception when operationProposal is null")
        void shouldThrowExceptionWhenOperationProposalIsNull() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When & Then
            assertThatThrownBy(() -> AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Operation proposal");
        }

        @Test
        @DisplayName("Should throw exception when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();

            // When & Then
            assertThatThrownBy(() -> AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Context");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is zero")
        void shouldThrowExceptionWhenExpirationSecondsIsZero() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When & Then
            assertThatThrownBy(() -> AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(0)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is negative")
        void shouldThrowExceptionWhenExpirationSecondsIsNegative() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When & Then
            assertThatThrownBy(() -> AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(-100)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build();

            // Then
            assertThat(parameters).isNotNull();
            assertThat(parameters.getUserId()).isNull();
            assertThat(parameters.getClientId()).isNull();
            assertThat(parameters.getRedirectUri()).isNull();
            assertThat(parameters.getState()).isNull();
        }

        @Test
        @DisplayName("Should set optional userId field")
        void shouldSetOptionalUserIdField() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .userId(USER_ID)
                    .build();

            // Then
            assertThat(parameters.getUserId()).isEqualTo(USER_ID);
        }

        @Test
        @DisplayName("Should set optional state field")
        void shouldSetOptionalStateField() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .state(STATE)
                    .build();

            // Then
            assertThat(parameters.getState()).isEqualTo(STATE);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            // When
            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build();

            // Then
            assertThat(parameters).isInstanceOf(AapParParameters.class);
            assertThat(parameters.getAgentUserBindingProposal()).isEqualTo(bindingProposal);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            AapParParameters.Builder builder = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS);

            // When
            AapParParameters parameters1 = builder.build();
            builder.userId("different_user");
            AapParParameters parameters2 = builder.build();

            // Then
            assertThat(parameters1.getUserId()).isNull();
            assertThat(parameters2.getUserId()).isEqualTo("different_user");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            AapParParameters parameters1 = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build();

            AapParParameters parameters2 = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .build();

            // Then
            assertThat(parameters1).isEqualTo(parameters2);
            assertThat(parameters1.hashCode()).isEqualTo(parameters2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when expirationSeconds differs")
        void shouldNotBeEqualWhenExpirationSecondsDiffers() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            AapParParameters parameters1 = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(3600)
                    .build();

            AapParParameters parameters2 = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(7200)
                    .build();

            // Then
            assertThat(parameters1).isNotEqualTo(parameters2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // Given
            AgentUserBindingProposal bindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user_token")
                    .agentWorkloadToken("agent_token")
                    .build();
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential("jwt_vc_string")
                    .build();
            AgentOperationProposal operationProposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();
            OperationRequestContext context = OperationRequestContext.builder()
                    .channel("web")
                    .build();

            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(bindingProposal)
                    .evidence(evidence)
                    .operationProposal(operationProposal)
                    .context(context)
                    .expirationSeconds(EXPIRATION_SECONDS)
                    .userId(USER_ID)
                    .state(STATE)
                    .build();

            // When
            String toString = parameters.toString();

            // Then
            assertThat(toString).contains("ParJwtParameters");
            assertThat(toString).contains(String.valueOf(EXPIRATION_SECONDS));
            assertThat(toString).contains(USER_ID);
            assertThat(toString).contains(STATE);
        }
    }
}
