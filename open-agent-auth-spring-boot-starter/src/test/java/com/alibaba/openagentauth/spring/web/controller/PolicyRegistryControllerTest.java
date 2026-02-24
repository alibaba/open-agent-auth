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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyMetadata;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PolicyRegistryController}.
 * <p>
 * This test class verifies the Policy Registry API functionality,
 * including policy registration, retrieval, and deletion.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyRegistryController Tests")
class PolicyRegistryControllerTest {

    private static final String POLICY_ID = "policy-123";
    private static final String REGO_POLICY = "package test\nallow = true";
    private static final String DESCRIPTION = "Test policy description";
    private static final String CREATED_BY = "admin";

    @Mock
    private PolicyRegistry policyRegistry;

    @InjectMocks
    private PolicyRegistryController controller;

    private Policy mockPolicy;
    private PolicyRegistration mockPolicyRegistration;

    @BeforeEach
    void setUp() {
        PolicyMetadata metadata =
            PolicyMetadata.builder()
                .createdAt(Instant.now())
                .createdBy(CREATED_BY)
                .build();

        mockPolicy = Policy.builder()
                .policyId(POLICY_ID)
                .regoPolicy(REGO_POLICY)
                .description(DESCRIPTION)
                .metadata(metadata)
                .build();

        mockPolicyRegistration = PolicyRegistration.builder()
                .policy(mockPolicy)
                .originalProposal(REGO_POLICY)
                .registeredAt(Instant.now())
                .status("SUCCESS")
                .build();
    }

    @Nested
    @DisplayName("GET /api/v1/policies/{policyId} - Get Policy")
    class GetPolicyTests {

        @Test
        @DisplayName("Should return policy when found")
        void shouldReturnPolicyWhenFound() throws Exception {
            // Arrange
            when(policyRegistry.get(POLICY_ID)).thenReturn(mockPolicy);

            // Act
            PolicyRegistryController.PolicyIdRequest request = new PolicyRegistryController.PolicyIdRequest();
            request.setPolicyId(POLICY_ID);
            ResponseEntity<Policy> response = controller.getPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getPolicyId()).isEqualTo(POLICY_ID);
            assertThat(response.getBody().getRegoPolicy()).isEqualTo(REGO_POLICY);
        }

        @Test
        @DisplayName("Should return 404 when policy not found")
        void shouldReturn404WhenPolicyNotFound() throws Exception {
            // Arrange
            when(policyRegistry.get(POLICY_ID)).thenThrow(new PolicyNotFoundException("Policy not found"));

            // Act
            PolicyRegistryController.PolicyIdRequest request = new PolicyRegistryController.PolicyIdRequest();
            request.setPolicyId(POLICY_ID);
            ResponseEntity<Policy> response = controller.getPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody()).isNull();
        }
    }

    @Nested
    @DisplayName("POST /api/v1/policies - Register Policy")
    class RegisterPolicyTests {

        @Test
        @DisplayName("Should register policy successfully")
        void shouldRegisterPolicySuccessfully() throws Exception {
            // Arrange
            PolicyRegistryController.PolicyRegistrationRequest request = new PolicyRegistryController.PolicyRegistrationRequest();
            request.setRegoPolicy(REGO_POLICY);
            request.setDescription(DESCRIPTION);
            request.setCreatedBy(CREATED_BY);

            when(policyRegistry.register(eq(REGO_POLICY), eq(DESCRIPTION), eq(CREATED_BY), isNull()))
                    .thenReturn(mockPolicyRegistration);

            // Act
            ResponseEntity<PolicyRegistration> response = controller.registerPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getPolicy()).isNotNull();
            assertThat(response.getBody().getPolicy().getPolicyId()).isEqualTo(POLICY_ID);
            assertThat(response.getBody().getPolicy().getRegoPolicy()).isEqualTo(REGO_POLICY);
        }

        @Test
        @DisplayName("Should return 500 when registration fails")
        void shouldReturn500WhenRegistrationFails() throws Exception {
            // Arrange
            PolicyRegistryController.PolicyRegistrationRequest request = new PolicyRegistryController.PolicyRegistrationRequest();
            request.setRegoPolicy(REGO_POLICY);
            request.setDescription(DESCRIPTION);

            when(policyRegistry.register(eq(REGO_POLICY), eq(DESCRIPTION), isNull(), isNull()))
                    .thenThrow(new RuntimeException("Registration failed"));

            // Act
            ResponseEntity<PolicyRegistration> response = controller.registerPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNull();
        }

        @Test
        @DisplayName("Should handle policy registration with expiration time")
        void shouldHandlePolicyRegistrationWithExpirationTime() throws Exception {
            // Arrange
            Instant expirationTime = Instant.now().plusSeconds(3600);
            PolicyRegistryController.PolicyRegistrationRequest request = new PolicyRegistryController.PolicyRegistrationRequest();
            request.setRegoPolicy(REGO_POLICY);
            request.setDescription(DESCRIPTION);
            request.setCreatedBy(CREATED_BY);
            request.setExpirationTime(expirationTime);

            when(policyRegistry.register(anyString(), anyString(), anyString(), eq(expirationTime)))
                    .thenReturn(mockPolicyRegistration);

            // Act
            ResponseEntity<PolicyRegistration> response = controller.registerPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
            org.mockito.Mockito.verify(policyRegistry).register(anyString(), anyString(), anyString(), eq(expirationTime));
        }
    }

    @Nested
    @DisplayName("DELETE /api/v1/policies/{policyId} - Delete Policy")
    class DeletePolicyTests {

        @Test
        @DisplayName("Should delete policy successfully")
        void shouldDeletePolicySuccessfully() throws Exception {
            // Act
            PolicyRegistryController.PolicyIdRequest request = new PolicyRegistryController.PolicyIdRequest();
            request.setPolicyId(POLICY_ID);
            ResponseEntity<Void> response = controller.deletePolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
            verify(policyRegistry).delete(POLICY_ID);
        }

        @Test
        @DisplayName("Should return 404 when policy to delete not found")
        void shouldReturn404WhenPolicyToDeleteNotFound() throws Exception {
            // Arrange
            doThrow(new PolicyNotFoundException("Policy not found")).when(policyRegistry).delete(POLICY_ID);

            // Act
            PolicyRegistryController.PolicyIdRequest request = new PolicyRegistryController.PolicyIdRequest();
            request.setPolicyId(POLICY_ID);
            ResponseEntity<Void> response = controller.deletePolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }

    @Nested
    @DisplayName("PolicyRegistrationRequest Tests")
    class PolicyRegistrationRequestTests {

        @Test
        @DisplayName("Should set and get all fields correctly")
        void shouldSetAndGetAllFieldsCorrectly() {
            // Arrange
            Instant expirationTime = Instant.now().plusSeconds(3600);
            PolicyRegistryController.PolicyRegistrationRequest request = new PolicyRegistryController.PolicyRegistrationRequest();

            // Act
            request.setRegoPolicy(REGO_POLICY);
            request.setDescription(DESCRIPTION);
            request.setCreatedBy(CREATED_BY);
            request.setExpirationTime(expirationTime);

            // Assert
            assertThat(request.getRegoPolicy()).isEqualTo(REGO_POLICY);
            assertThat(request.getDescription()).isEqualTo(DESCRIPTION);
            assertThat(request.getCreatedBy()).isEqualTo(CREATED_BY);
            assertThat(request.getExpirationTime()).isEqualTo(expirationTime);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle null policy ID gracefully")
        void shouldHandleNullPolicyIdGracefully() throws Exception {
            // Arrange
            when(policyRegistry.get(isNull())).thenThrow(new PolicyNotFoundException("Policy ID is null"));

            // Act
            PolicyRegistryController.PolicyIdRequest request = new PolicyRegistryController.PolicyIdRequest();
            request.setPolicyId(null);
            ResponseEntity<Policy> response = controller.getPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }

        @Test
        @DisplayName("Should handle empty policy ID gracefully")
        void shouldHandleEmptyPolicyIdGracefully() throws Exception {
            // Arrange
            when(policyRegistry.get("")).thenThrow(new PolicyNotFoundException("Policy ID is empty"));

            // Act
            PolicyRegistryController.PolicyIdRequest request = new PolicyRegistryController.PolicyIdRequest();
            request.setPolicyId("");
            ResponseEntity<Policy> response = controller.getPolicy(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        }
    }
}
