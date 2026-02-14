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
package com.alibaba.openagentauth.core.binding;

import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link BindingInstance}.
 */
@DisplayName("BindingInstance Tests")
class BindingInstanceTest {

    private static final String BINDING_INSTANCE_ID = "urn:uuid:binding-123";
    private static final String USER_IDENTITY = "https://idp.example.com|user-12345";
    private static final String WORKLOAD_IDENTITY = "spiffe://example.com/ns/default/sa/agent";
    private static final Instant CREATED_AT = Instant.parse("2025-01-01T00:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2025-01-02T00:00:00Z");

    @Test
    @DisplayName("Should create valid BindingInstance using builder with all fields")
    void shouldCreateValidBindingInstanceUsingBuilderWithAllFields() {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .id(BINDING_INSTANCE_ID)
                .issuer("https://as.example.com")
                .issuedTo(USER_IDENTITY)
                .build();

        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .agentIdentity(agentIdentity)
                .createdAt(CREATED_AT)
                .expiresAt(EXPIRES_AT)
                .build();

        assertNotNull(binding);
        assertEquals(BINDING_INSTANCE_ID, binding.getBindingInstanceId());
        assertEquals(USER_IDENTITY, binding.getUserIdentity());
        assertEquals(WORKLOAD_IDENTITY, binding.getWorkloadIdentity());
        assertEquals(agentIdentity, binding.getAgentIdentity());
        assertEquals(CREATED_AT, binding.getCreatedAt());
        assertEquals(EXPIRES_AT, binding.getExpiresAt());
    }

    @Test
    @DisplayName("Should auto-generate createdAt timestamp when not provided")
    void shouldAutoGenerateCreatedAtTimestampWhenNotProvided() {
        Instant beforeBuild = Instant.now();

        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .build();

        Instant afterBuild = Instant.now();

        assertNotNull(binding.getCreatedAt());
        assertFalse(binding.getCreatedAt().isBefore(beforeBuild));
        assertFalse(binding.getCreatedAt().isAfter(afterBuild));
    }

    @Test
    @DisplayName("Should throw exception when bindingInstanceId is null or empty")
    void shouldThrowExceptionWhenBindingInstanceIdIsNullOrEmpty() {
        assertThrows(IllegalStateException.class, () -> 
            BindingInstance.builder()
                    .userIdentity(USER_IDENTITY)
                    .workloadIdentity(WORKLOAD_IDENTITY)
                    .build()
        );

        assertThrows(IllegalStateException.class, () -> 
            BindingInstance.builder()
                    .bindingInstanceId("")
                    .userIdentity(USER_IDENTITY)
                    .workloadIdentity(WORKLOAD_IDENTITY)
                    .build()
        );
    }

    @Test
    @DisplayName("Should throw exception when userIdentity is null or empty")
    void shouldThrowExceptionWhenUserIdentityIsNullOrEmpty() {
        assertThrows(IllegalStateException.class, () -> 
            BindingInstance.builder()
                    .bindingInstanceId(BINDING_INSTANCE_ID)
                    .workloadIdentity(WORKLOAD_IDENTITY)
                    .build()
        );

        assertThrows(IllegalStateException.class, () -> 
            BindingInstance.builder()
                    .bindingInstanceId(BINDING_INSTANCE_ID)
                    .userIdentity("")
                    .workloadIdentity(WORKLOAD_IDENTITY)
                    .build()
        );
    }

    @Test
    @DisplayName("Should throw exception when workloadIdentity is null or empty")
    void shouldThrowExceptionWhenWorkloadIdentityIsNullOrEmpty() {
        assertThrows(IllegalStateException.class, () -> 
            BindingInstance.builder()
                    .bindingInstanceId(BINDING_INSTANCE_ID)
                    .userIdentity(USER_IDENTITY)
                    .build()
        );

        assertThrows(IllegalStateException.class, () -> 
            BindingInstance.builder()
                    .bindingInstanceId(BINDING_INSTANCE_ID)
                    .userIdentity(USER_IDENTITY)
                    .workloadIdentity("")
                    .build()
        );
    }

    @Test
    @DisplayName("Should return true for isExpired when binding is expired")
    void shouldReturnTrueForIsExpiredWhenBindingIsExpired() {
        Instant pastExpiration = Instant.now().minusSeconds(3600);

        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .expiresAt(pastExpiration)
                .build();

        assertTrue(binding.isExpired());
        assertFalse(binding.isValid());
    }

    @Test
    @DisplayName("Should return false for isExpired when binding is not expired")
    void shouldReturnFalseForIsExpiredWhenBindingIsNotExpired() {
        Instant futureExpiration = Instant.now().plusSeconds(3600);

        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .expiresAt(futureExpiration)
                .build();

        assertFalse(binding.isExpired());
        assertTrue(binding.isValid());
    }

    @Test
    @DisplayName("Should return false for isExpired when expiresAt is null")
    void shouldReturnFalseForIsExpiredWhenExpiresAtIsNull() {
        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .expiresAt(null)
                .build();

        assertFalse(binding.isExpired());
        assertTrue(binding.isValid());
    }

    @Test
    @DisplayName("Should implement equals correctly")
    void shouldImplementEqualsCorrectly() {
        AgentIdentity agentIdentity = AgentIdentity.builder()
                .id(BINDING_INSTANCE_ID)
                .build();

        BindingInstance binding1 = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .agentIdentity(agentIdentity)
                .createdAt(CREATED_AT)
                .expiresAt(EXPIRES_AT)
                .build();

        BindingInstance binding2 = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .agentIdentity(agentIdentity)
                .createdAt(CREATED_AT)
                .expiresAt(EXPIRES_AT)
                .build();

        BindingInstance binding3 = BindingInstance.builder()
                .bindingInstanceId("urn:uuid:binding-456")
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .build();

        assertEquals(binding1, binding2);
        assertEquals(binding1.hashCode(), binding2.hashCode());
        assertNotEquals(binding1, binding3);
        assertNotEquals(binding1, null);
        assertNotEquals(binding1, new Object());
    }

    @Test
    @DisplayName("Should return meaningful toString")
    void shouldReturnMeaningfulToString() {
        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .build();

        String toString = binding.toString();

        assertTrue(toString.contains("BindingInstance"));
        assertTrue(toString.contains(BINDING_INSTANCE_ID));
        assertTrue(toString.contains(USER_IDENTITY));
        assertTrue(toString.contains(WORKLOAD_IDENTITY));
    }

    @Test
    @DisplayName("Should support builder pattern chaining")
    void shouldSupportBuilderPatternChaining() {
        BindingInstance binding = BindingInstance.builder()
                .bindingInstanceId(BINDING_INSTANCE_ID)
                .userIdentity(USER_IDENTITY)
                .workloadIdentity(WORKLOAD_IDENTITY)
                .createdAt(CREATED_AT)
                .expiresAt(EXPIRES_AT)
                .build();

        assertNotNull(binding);
        assertEquals(BINDING_INSTANCE_ID, binding.getBindingInstanceId());
        assertEquals(USER_IDENTITY, binding.getUserIdentity());
        assertEquals(WORKLOAD_IDENTITY, binding.getWorkloadIdentity());
    }
}
