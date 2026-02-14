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

import com.alibaba.openagentauth.core.binding.BindingInstance;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IdentityConsistencyValidator}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("IdentityConsistencyValidator Tests")
class IdentityConsistencyValidatorTest {

    @Mock
    private BindingInstanceStore bindingInstanceStore;

    private static final String USER_ID = "https://idp.example.com|user-123";
    private static final String USER_ID_SHORT = "user-123";
    private static final String AGENT_ID = "urn:uuid:agent-123";
    private static final String BINDING_INSTANCE_ID = "urn:uuid:binding-123";
    private static final String WORKLOAD_ID = "workload-instance-456";

    @Test
    @DisplayName("Should pass validation with valid tokens (without binding store)")
    void shouldPassValidationWithValidTokens() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();
        ValidationContext context = createValidContext();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.isFailure()).isFalse();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should fail validation when WIT is missing")
    void shouldFailValidationWhenWitIsMissing() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();
        AgentOperationAuthToken aoat = createValidAoat();

        ValidationContext context = ValidationContext.builder()
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WIT is required");
    }

    @Test
    @DisplayName("Should fail validation when AOAT is missing")
    void shouldFailValidationWhenAoatIsMissing() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();
        WorkloadIdentityToken wit = createValidWit();

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("AOAT is required");
    }

    @Test
    @DisplayName("Should pass validation with valid user identity in AOAT (without binding store)")
    void shouldPassValidationWithValidUserIdentityInAoat() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();
        WorkloadIdentityToken wit = createValidWit();
        AgentOperationAuthToken aoat = createValidAoat();

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should return correct validator name")
    void shouldReturnCorrectValidatorName() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();

        // Act
        String name = validator.getName();

        // Assert
        assertThat(name).isEqualTo("Layer 4: Identity Consistency Validator");
    }

    @Test
    @DisplayName("Should return correct validator order")
    void shouldReturnCorrectValidatorOrder() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();

        // Act
        double order = validator.getOrder();

        // Assert
        assertThat(order).isEqualTo(4.0);
    }

    @Test
    @DisplayName("Should handle context with null tokens gracefully")
    void shouldHandleContextWithNullTokensGracefully() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();
        ValidationContext context = ValidationContext.builder().build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).contains("WIT is required");
    }

    @Test
    @DisplayName("Should pass validation regardless of WIT subject (without binding store)")
    void shouldPassValidationRegardlessOfWitSubject() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator();
        WorkloadIdentityToken wit = createValidWit();
        AgentOperationAuthToken aoat = createValidAoat();

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    // ========== Two-Layer Identity Verification Tests ==========

    @Test
    @DisplayName("Should pass two-layer verification with matching identities")
    void shouldPassTwoLayerVerificationWithMatchingIdentities() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator(bindingInstanceStore);
        WorkloadIdentityToken wit = createValidWit();
        AgentOperationAuthToken aoat = createValidAoatWithBindingId();
        BindingInstance binding = createTestBinding();

        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(binding);

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should fail two-layer verification when binding instance not found")
    void shouldFailTwoLayerVerificationWhenBindingInstanceNotFound() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator(bindingInstanceStore);
        WorkloadIdentityToken wit = createValidWit();
        AgentOperationAuthToken aoat = createValidAoatWithBindingId();

        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(null);

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).isNotEmpty();
    }

    @Test
    @DisplayName("Should fail two-layer verification when binding instance is expired")
    void shouldFailTwoLayerVerificationWhenBindingInstanceIsExpired() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator(bindingInstanceStore);
        WorkloadIdentityToken wit = createValidWit();
        AgentOperationAuthToken aoat = createValidAoatWithBindingId();
        BindingInstance expiredBinding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_ID)
                .workloadIdentity(WORKLOAD_ID)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().minusSeconds(3600))
                .build();

        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(expiredBinding);

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).isNotEmpty();
    }

    @Test
    @DisplayName("Should fail two-layer verification when user identity mismatch")
    void shouldFailTwoLayerVerificationWhenUserIdentityMismatch() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator(bindingInstanceStore);
        WorkloadIdentityToken wit = createValidWit();
        
        String differentUserId = "https://idp.example.com|different-user";
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id(BINDING_INSTANCE_ID)
                .issuer("https://as.example.com")
                .issuedTo(differentUserId)
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId("test-policy-123")
                .build();

        AgentOperationAuthToken aoat = AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject(USER_ID)
                        .audience("resource-server")
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .issuedAt(Instant.now())
                        .jwtId("aoat-jti-123")
                        .agentIdentity(agentIdentity)
                        .authorization(authorization)
                        .build())
                .build();

        BindingInstance binding = createTestBinding();
        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(binding);

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).anyMatch(error -> error.contains("User identity mismatch"));
    }

    @Test
    @DisplayName("Should fail two-layer verification when workload identity mismatch")
    void shouldFailTwoLayerVerificationWhenWorkloadIdentityMismatch() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator(bindingInstanceStore);
        
        String differentWorkloadId = "different-workload-789";
        WorkloadIdentityToken wit = WorkloadIdentityToken.builder()
                .claims(WorkloadIdentityToken.Claims.builder()
                        .issuer("wimse://example.com")
                        .subject(differentWorkloadId)
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .jwtId("wit-jti-123")
                        .build())
                .header(WorkloadIdentityToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .build();
        
        AgentOperationAuthToken aoat = createValidAoatWithBindingId();
        BindingInstance binding = createTestBinding();
        when(bindingInstanceStore.retrieve(BINDING_INSTANCE_ID)).thenReturn(binding);

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).anyMatch(error -> error.contains("Workload identity mismatch"));
    }

    @Test
    @DisplayName("Should fail two-layer verification when AOAT agent_identity.id is null")
    void shouldFailTwoLayerVerificationWhenAoatAgentIdentityIdIsNull() {
        // Arrange
        IdentityConsistencyValidator validator = new IdentityConsistencyValidator(bindingInstanceStore);
        WorkloadIdentityToken wit = createValidWit();
        
        AgentIdentity agentIdentityWithNullId = AgentIdentity.builder()
                .version("1.0")
                .id(null)
                .issuer("https://as.example.com")
                .issuedTo(USER_ID)
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId("test-policy-123")
                .build();

        AgentOperationAuthToken aoat = AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject(USER_ID)
                        .audience("resource-server")
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .issuedAt(Instant.now())
                        .jwtId("aoat-jti-123")
                        .agentIdentity(agentIdentityWithNullId)
                        .authorization(authorization)
                        .build())
                .build();

        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();

        // Act
        LayerValidationResult result = validator.validate(context);

        // Assert
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).anyMatch(error -> error.contains("Failed to retrieve or validate binding instance"));
    }

    /**
     * Helper method to create a valid WIT for testing.
     */
    private WorkloadIdentityToken createValidWit() {
        return WorkloadIdentityToken.builder()
                .claims(WorkloadIdentityToken.Claims.builder()
                        .issuer("wimse://example.com")
                        .subject(WORKLOAD_ID)
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .jwtId("wit-jti-123")
                        .build())
                .header(WorkloadIdentityToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .build();
    }

    /**
     * Helper method to create a valid AOAT for testing.
     */
    private AgentOperationAuthToken createValidAoat() {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id(AGENT_ID)
                .issuer("https://as.example.com")
                .issuedTo(USER_ID)
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId("test-policy-123")
                .build();

        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject(USER_ID)
                        .audience("resource-server")
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .issuedAt(Instant.now())
                        .jwtId("aoat-jti-123")
                        .agentIdentity(agentIdentity)
                        .authorization(authorization)
                        .build())
                .build();
    }

    /**
     * Helper method to create a valid AOAT with binding instance ID for testing.
     */
    private AgentOperationAuthToken createValidAoatWithBindingId() {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .version("1.0")
                .id(BINDING_INSTANCE_ID)
                .issuer("https://as.example.com")
                .issuedTo(USER_ID)
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();

        AgentOperationAuthorization authorization = AgentOperationAuthorization.builder()
                .policyId("test-policy-123")
                .build();

        return AgentOperationAuthToken.builder()
                .header(AgentOperationAuthToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject(USER_ID)
                        .audience("resource-server")
                        .expirationTime(Instant.now().plusSeconds(3600))
                        .issuedAt(Instant.now())
                        .jwtId("aoat-jti-123")
                        .agentIdentity(agentIdentity)
                        .authorization(authorization)
                        .build())
                .build();
    }

    /**
     * Helper method to create a valid validation context.
     */
    private ValidationContext createValidContext() {
        WorkloadIdentityToken wit = createValidWit();
        AgentOperationAuthToken aoat = createValidAoat();

        return ValidationContext.builder()
                .wit(wit)
                .agentOaToken(aoat)
                .build();
    }

    /**
     * Helper method to create a test binding instance.
     */
    private BindingInstance createTestBinding() {
        return BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_ID_SHORT)
                .workloadIdentity(WORKLOAD_ID)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
    }
}