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

import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link BindingInstanceController.BindingInstanceRequest}.
 * <p>
 * This test class verifies the BindingInstanceRequest inner class functionality,
 * including field getters and setters, default values, and boundary conditions.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("BindingInstanceController.BindingInstanceRequest Tests")
class BindingInstanceRequestTest {

    private BindingInstanceController.BindingInstanceRequest request;

    @BeforeEach
    void setUp() {
        request = new BindingInstanceController.BindingInstanceRequest();
    }

    @Nested
    @DisplayName("Default Values Tests")
    class DefaultValuesTests {

        @Test
        @DisplayName("bindingInstanceId should be null by default")
        void bindingInstanceIdShouldBeNullByDefault() {
            assertThat(request.getBindingInstanceId())
                .as("bindingInstanceId should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("userIdentity should be null by default")
        void userIdentityShouldBeNullByDefault() {
            assertThat(request.getUserIdentity())
                .as("userIdentity should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("workloadIdentity should be null by default")
        void workloadIdentityShouldBeNullByDefault() {
            assertThat(request.getWorkloadIdentity())
                .as("workloadIdentity should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("agentIdentity should be null by default")
        void agentIdentityShouldBeNullByDefault() {
            assertThat(request.getAgentIdentity())
                .as("agentIdentity should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("createdAt should be null by default")
        void createdAtShouldBeNullByDefault() {
            assertThat(request.getCreatedAt())
                .as("createdAt should be null by default")
                .isNull();
        }

        @Test
        @DisplayName("expiresAt should be null by default")
        void expiresAtShouldBeNullByDefault() {
            assertThat(request.getExpiresAt())
                .as("expiresAt should be null by default")
                .isNull();
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterAndSetterTests {

        @Test
        @DisplayName("Should set and get bindingInstanceId")
        void shouldSetAndGetBindingInstanceId() {
            String testBindingInstanceId = "urn:uuid:binding-123";
            request.setBindingInstanceId(testBindingInstanceId);
            assertThat(request.getBindingInstanceId())
                .as("bindingInstanceId should match")
                .isEqualTo(testBindingInstanceId);
        }

        @Test
        @DisplayName("Should set and get userIdentity")
        void shouldSetAndGetUserIdentity() {
            String testUserIdentity = "https://idp.example.com|user-12345";
            request.setUserIdentity(testUserIdentity);
            assertThat(request.getUserIdentity())
                .as("userIdentity should match")
                .isEqualTo(testUserIdentity);
        }

        @Test
        @DisplayName("Should set and get workloadIdentity")
        void shouldSetAndGetWorkloadIdentity() {
            String testWorkloadIdentity = "spiffe://example.com/ns/default/sa/agent";
            request.setWorkloadIdentity(testWorkloadIdentity);
            assertThat(request.getWorkloadIdentity())
                .as("workloadIdentity should match")
                .isEqualTo(testWorkloadIdentity);
        }

        @Test
        @DisplayName("Should set and get agentIdentity")
        void shouldSetAndGetAgentIdentity() {
            AgentIdentity testAgentIdentity = AgentIdentity.builder()
                .id("agent-123")
                .issuer("https://as.example.com")
                .issuedTo("https://idp.example.com|user-12345")
                .build();
            
            request.setAgentIdentity(testAgentIdentity);
            assertThat(request.getAgentIdentity())
                .as("agentIdentity should match")
                .isSameAs(testAgentIdentity);
            assertThat(request.getAgentIdentity().getId())
                .as("agentIdentity id should be agent-123")
                .isEqualTo("agent-123");
        }

        @Test
        @DisplayName("Should set and get createdAt")
        void shouldSetAndGetCreatedAt() {
            Instant testCreatedAt = Instant.now();
            request.setCreatedAt(testCreatedAt);
            assertThat(request.getCreatedAt())
                .as("createdAt should match")
                .isEqualTo(testCreatedAt);
        }

        @Test
        @DisplayName("Should set and get expiresAt")
        void shouldSetAndGetExpiresAt() {
            Instant testExpiresAt = Instant.now().plusSeconds(3600);
            request.setExpiresAt(testExpiresAt);
            assertThat(request.getExpiresAt())
                .as("expiresAt should match")
                .isEqualTo(testExpiresAt);
        }
    }

    @Nested
    @DisplayName("Boundary Conditions and Null Value Tests")
    class BoundaryConditionsAndNullValueTests {

        @Test
        @DisplayName("Should handle null bindingInstanceId")
        void shouldHandleNullBindingInstanceId() {
            request.setBindingInstanceId("test-id");
            request.setBindingInstanceId(null);
            assertThat(request.getBindingInstanceId())
                .as("bindingInstanceId should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null userIdentity")
        void shouldHandleNullUserIdentity() {
            request.setUserIdentity("test-user");
            request.setUserIdentity(null);
            assertThat(request.getUserIdentity())
                .as("userIdentity should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null workloadIdentity")
        void shouldHandleNullWorkloadIdentity() {
            request.setWorkloadIdentity("test-workload");
            request.setWorkloadIdentity(null);
            assertThat(request.getWorkloadIdentity())
                .as("workloadIdentity should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null agentIdentity")
        void shouldHandleNullAgentIdentity() {
            AgentIdentity agentIdentity = AgentIdentity.builder()
                .id("agent-123")
                .issuer("https://as.example.com")
                .issuedTo("user-123")
                .build();
            request.setAgentIdentity(agentIdentity);
            request.setAgentIdentity(null);
            assertThat(request.getAgentIdentity())
                .as("agentIdentity should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null createdAt")
        void shouldHandleNullCreatedAt() {
            request.setCreatedAt(Instant.now());
            request.setCreatedAt(null);
            assertThat(request.getCreatedAt())
                .as("createdAt should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle null expiresAt")
        void shouldHandleNullExpiresAt() {
            request.setExpiresAt(Instant.now());
            request.setExpiresAt(null);
            assertThat(request.getExpiresAt())
                .as("expiresAt should be null")
                .isNull();
        }

        @Test
        @DisplayName("Should handle empty string bindingInstanceId")
        void shouldHandleEmptyStringBindingInstanceId() {
            request.setBindingInstanceId("");
            assertThat(request.getBindingInstanceId())
                .as("bindingInstanceId should be empty string")
                .isEmpty();
        }

        @Test
        @DisplayName("Should handle empty string userIdentity")
        void shouldHandleEmptyStringUserIdentity() {
            request.setUserIdentity("");
            assertThat(request.getUserIdentity())
                .as("userIdentity should be empty string")
                .isEmpty();
        }

        @Test
        @DisplayName("Should handle empty string workloadIdentity")
        void shouldHandleEmptyStringWorkloadIdentity() {
            request.setWorkloadIdentity("");
            assertThat(request.getWorkloadIdentity())
                .as("workloadIdentity should be empty string")
                .isEmpty();
        }

        @Test
        @DisplayName("Should handle past createdAt")
        void shouldHandlePastCreatedAt() {
            Instant pastTime = Instant.now().minusSeconds(3600);
            request.setCreatedAt(pastTime);
            assertThat(request.getCreatedAt())
                .as("createdAt should be in the past")
                .isEqualTo(pastTime);
        }

        @Test
        @DisplayName("Should handle future expiresAt")
        void shouldHandleFutureExpiresAt() {
            Instant futureTime = Instant.now().plusSeconds(86400);
            request.setExpiresAt(futureTime);
            assertThat(request.getExpiresAt())
                .as("expiresAt should be in the future")
                .isEqualTo(futureTime);
        }

        @Test
        @DisplayName("Should handle special characters in userIdentity")
        void shouldHandleSpecialCharactersInUserIdentity() {
            String specialUserIdentity = "https://idp.example.com|user-123!@#$%^&*()";
            request.setUserIdentity(specialUserIdentity);
            assertThat(request.getUserIdentity())
                .as("userIdentity with special characters should match")
                .isEqualTo(specialUserIdentity);
        }

        @Test
        @DisplayName("Should handle unicode in workloadIdentity")
        void shouldHandleUnicodeInWorkloadIdentity() {
            String unicodeWorkloadIdentity = "spiffe://example.com/ns/default/sa/proxy";
            request.setWorkloadIdentity(unicodeWorkloadIdentity);
            assertThat(request.getWorkloadIdentity())
                .as("workloadIdentity with unicode should match")
                .isEqualTo(unicodeWorkloadIdentity);
        }

        @Test
        @DisplayName("Should handle very long bindingInstanceId")
        void shouldHandleVeryLongBindingInstanceId() {
            StringBuilder longId = new StringBuilder("urn:uuid:");
            for (int i = 0; i < 1000; i++) {
                longId.append("a");
            }
            request.setBindingInstanceId(longId.toString());
            assertThat(request.getBindingInstanceId())
                .as("bindingInstanceId should have length 1009")
                .hasSize(1009);
        }
    }

    @Nested
    @DisplayName("Complete Configuration Tests")
    class CompleteConfigurationTests {

        @Test
        @DisplayName("Should create complete binding instance request")
        void shouldCreateCompleteBindingInstanceRequest() {
            String bindingInstanceId = "urn:uuid:binding-123";
            String userIdentity = "https://idp.example.com|user-12345";
            String workloadIdentity = "spiffe://example.com/ns/default/sa/agent";
            Instant createdAt = Instant.now();
            Instant expiresAt = Instant.now().plusSeconds(3600);

            AgentIdentity agentIdentity = AgentIdentity.builder()
                .id("agent-123")
                .issuer("https://as.example.com")
                .issuedTo(userIdentity)
                .build();

            request.setBindingInstanceId(bindingInstanceId);
            request.setUserIdentity(userIdentity);
            request.setWorkloadIdentity(workloadIdentity);
            request.setAgentIdentity(agentIdentity);
            request.setCreatedAt(createdAt);
            request.setExpiresAt(expiresAt);

            assertThat(request.getBindingInstanceId()).isEqualTo(bindingInstanceId);
            assertThat(request.getUserIdentity()).isEqualTo(userIdentity);
            assertThat(request.getWorkloadIdentity()).isEqualTo(workloadIdentity);
            assertThat(request.getAgentIdentity()).isSameAs(agentIdentity);
            assertThat(request.getCreatedAt()).isEqualTo(createdAt);
            assertThat(request.getExpiresAt()).isEqualTo(expiresAt);
        }

        @Test
        @DisplayName("Should create minimal binding instance request")
        void shouldCreateMinimalBindingInstanceRequest() {
            String bindingInstanceId = "urn:uuid:binding-456";
            String userIdentity = "https://idp.example.com|user-67890";
            String workloadIdentity = "spiffe://example.com/ns/default/sa/agent";

            request.setBindingInstanceId(bindingInstanceId);
            request.setUserIdentity(userIdentity);
            request.setWorkloadIdentity(workloadIdentity);

            assertThat(request.getBindingInstanceId()).isEqualTo(bindingInstanceId);
            assertThat(request.getUserIdentity()).isEqualTo(userIdentity);
            assertThat(request.getWorkloadIdentity()).isEqualTo(workloadIdentity);
            assertThat(request.getAgentIdentity()).isNull();
            assertThat(request.getCreatedAt()).isNull();
            assertThat(request.getExpiresAt()).isNull();
        }

        @Test
        @DisplayName("Should allow updating configuration")
        void shouldAllowUpdatingConfiguration() {
            request.setBindingInstanceId("urn:uuid:binding-123");
            request.setUserIdentity("https://idp.example.com|user-123");
            request.setWorkloadIdentity("spiffe://example.com/ns/default/sa/agent1");

            assertThat(request.getBindingInstanceId()).isEqualTo("urn:uuid:binding-123");
            assertThat(request.getUserIdentity()).isEqualTo("https://idp.example.com|user-123");
            assertThat(request.getWorkloadIdentity()).isEqualTo("spiffe://example.com/ns/default/sa/agent1");

            request.setBindingInstanceId("urn:uuid:binding-456");
            request.setUserIdentity("https://idp.example.com|user-456");
            request.setWorkloadIdentity("spiffe://example.com/ns/default/sa/agent2");

            assertThat(request.getBindingInstanceId()).isEqualTo("urn:uuid:binding-456");
            assertThat(request.getUserIdentity()).isEqualTo("https://idp.example.com|user-456");
            assertThat(request.getWorkloadIdentity()).isEqualTo("spiffe://example.com/ns/default/sa/agent2");
        }
    }

    @Nested
    @DisplayName("Time-based Tests")
    class TimeBasedTests {

        @Test
        @DisplayName("Should handle createdAt before expiresAt")
        void shouldHandleCreatedAtBeforeExpiresAt() {
            Instant createdAt = Instant.now();
            Instant expiresAt = createdAt.plusSeconds(3600);
            
            request.setCreatedAt(createdAt);
            request.setExpiresAt(expiresAt);
            
            assertThat(request.getCreatedAt())
                .as("createdAt should be before expiresAt")
                .isBefore(request.getExpiresAt());
        }

        @Test
        @DisplayName("Should handle same createdAt and expiresAt")
        void shouldHandleSameCreatedAtAndExpiresAt() {
            Instant sameTime = Instant.now();
            
            request.setCreatedAt(sameTime);
            request.setExpiresAt(sameTime);
            
            assertThat(request.getCreatedAt())
                .as("createdAt should equal expiresAt")
                .isEqualTo(request.getExpiresAt());
        }

        @Test
        @DisplayName("Should handle epoch time for createdAt")
        void shouldHandleEpochTimeForCreatedAt() {
            Instant epochTime = Instant.EPOCH;
            request.setCreatedAt(epochTime);
            assertThat(request.getCreatedAt())
                .as("createdAt should be epoch time")
                .isEqualTo(epochTime);
        }

        @Test
        @DisplayName("Should handle max instant for expiresAt")
        void shouldHandleMaxInstantForExpiresAt() {
            Instant maxTime = Instant.MAX;
            request.setExpiresAt(maxTime);
            assertThat(request.getExpiresAt())
                .as("expiresAt should be max instant")
                .isEqualTo(maxTime);
        }
    }

    @Nested
    @DisplayName("Multiple Instance Tests")
    class MultipleInstanceTests {

        @Test
        @DisplayName("Should create independent instances")
        void shouldCreateIndependentInstances() {
            BindingInstanceController.BindingInstanceRequest request1 = 
                new BindingInstanceController.BindingInstanceRequest();
            BindingInstanceController.BindingInstanceRequest request2 = 
                new BindingInstanceController.BindingInstanceRequest();

            request1.setBindingInstanceId("urn:uuid:binding-1");
            request2.setBindingInstanceId("urn:uuid:binding-2");

            assertThat(request1.getBindingInstanceId())
                .as("request1 bindingInstanceId should be urn:uuid:binding-1")
                .isEqualTo("urn:uuid:binding-1");
            assertThat(request2.getBindingInstanceId())
                .as("request2 bindingInstanceId should be urn:uuid:binding-2")
                .isEqualTo("urn:uuid:binding-2");
        }

        @Test
        @DisplayName("Should allow independent agentIdentity modifications")
        void shouldAllowIndependentAgentIdentityModifications() {
            BindingInstanceController.BindingInstanceRequest request1 = 
                new BindingInstanceController.BindingInstanceRequest();
            BindingInstanceController.BindingInstanceRequest request2 = 
                new BindingInstanceController.BindingInstanceRequest();

            AgentIdentity agent1 = AgentIdentity.builder()
                .id("agent-1")
                .issuer("https://as.example.com")
                .issuedTo("user-1")
                .build();
            
            AgentIdentity agent2 = AgentIdentity.builder()
                .id("agent-2")
                .issuer("https://as.example.com")
                .issuedTo("user-2")
                .build();

            request1.setAgentIdentity(agent1);
            request2.setAgentIdentity(agent2);

            assertThat(request1.getAgentIdentity().getId())
                .as("request1 agentIdentity id should be agent-1")
                .isEqualTo("agent-1");
            assertThat(request2.getAgentIdentity().getId())
                .as("request2 agentIdentity id should be agent-2")
                .isEqualTo("agent-2");
        }
    }

    @Nested
    @DisplayName("Identity Format Tests")
    class IdentityFormatTests {

        @Test
        @DisplayName("Should handle SPIFFE workload identity format")
        void shouldHandleSpiffeWorkloadIdentityFormat() {
            String spiffeIdentity = "spiffe://example.com/ns/default/sa/my-service";
            request.setWorkloadIdentity(spiffeIdentity);
            assertThat(request.getWorkloadIdentity())
                .as("workloadIdentity should be SPIFFE format")
                .isEqualTo(spiffeIdentity);
        }

        @Test
        @DisplayName("Should handle OIDC user identity format")
        void shouldHandleOidcUserIdentityFormat() {
            String oidcIdentity = "https://idp.example.com|user-12345";
            request.setUserIdentity(oidcIdentity);
            assertThat(request.getUserIdentity())
                .as("userIdentity should be OIDC format")
                .isEqualTo(oidcIdentity);
        }

        @Test
        @DisplayName("Should handle URN UUID binding instance ID format")
        void shouldHandleUrnUuidBindingInstanceIdFormat() {
            String urnUuid = "urn:uuid:550e8400-e29b-41d4-a716-446655440000";
            request.setBindingInstanceId(urnUuid);
            assertThat(request.getBindingInstanceId())
                .as("bindingInstanceId should be URN UUID format")
                .isEqualTo(urnUuid);
        }
    }
}
