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
package com.alibaba.openagentauth.core.model.proposal;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AgentUserBindingProposal}.
 * <p>
 * This test class validates the behavior of the AgentUserBindingProposal class,
 * which represents a proposal for binding an agent to a user in the authorization flow.
 * </p>
 */
@DisplayName("AgentUserBindingProposal Tests")
class AgentUserBindingProposalTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build proposal with all required fields")
        void shouldBuildProposalWithRequiredFields() {
            // Given
            String userIdentityToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
            String agentWorkloadToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

            // When
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(userIdentityToken)
                    .agentWorkloadToken(agentWorkloadToken)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(userIdentityToken, proposal.getUserIdentityToken());
            assertEquals(agentWorkloadToken, proposal.getAgentWorkloadToken());
            assertNull(proposal.getDeviceFingerprint());
        }

        @Test
        @DisplayName("Should build proposal with all fields including optional")
        void shouldBuildProposalWithAllFields() {
            // Given
            String userIdentityToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
            String agentWorkloadToken = "eyJhbGciOiRSUzI1NiIsInR5cCI6IkpXVCJ9...";
            String deviceFingerprint = "fp_abc123xyz";

            // When
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(userIdentityToken)
                    .agentWorkloadToken(agentWorkloadToken)
                    .deviceFingerprint(deviceFingerprint)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(userIdentityToken, proposal.getUserIdentityToken());
            assertEquals(agentWorkloadToken, proposal.getAgentWorkloadToken());
            assertEquals(deviceFingerprint, proposal.getDeviceFingerprint());
        }

        @Test
        @DisplayName("Should build proposal with null optional field")
        void shouldBuildProposalWithNullOptionalField() {
            // Given
            String userIdentityToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
            String agentWorkloadToken = "eyJhbGciOiRSUzI1NiIsInR5cCI6IkpXVCJ9...";

            // When
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(userIdentityToken)
                    .agentWorkloadToken(agentWorkloadToken)
                    .deviceFingerprint(null)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(userIdentityToken, proposal.getUserIdentityToken());
            assertEquals(agentWorkloadToken, proposal.getAgentWorkloadToken());
            assertNull(proposal.getDeviceFingerprint());
        }

        @Test
        @DisplayName("Should build proposal with null required field")
        void shouldBuildProposalWithNullRequiredField() {
            // When
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(null)
                    .agentWorkloadToken(null)
                    .build();

            // Then
            assertNotNull(proposal);
            assertNull(proposal.getUserIdentityToken());
            assertNull(proposal.getAgentWorkloadToken());
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            // Given
            String userIdentityToken = "token1";
            String agentWorkloadToken = "token2";

            // When
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(userIdentityToken)
                    .agentWorkloadToken(agentWorkloadToken)
                    .deviceFingerprint("fp123")
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(userIdentityToken, proposal.getUserIdentityToken());
            assertEquals(agentWorkloadToken, proposal.getAgentWorkloadToken());
            assertEquals("fp123", proposal.getDeviceFingerprint());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return user identity token")
        void shouldReturnUserIdentityToken() {
            // Given
            String token = "user-token";
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(token)
                    .agentWorkloadToken("workload-token")
                    .build();

            // When
            String result = proposal.getUserIdentityToken();

            // Then
            assertEquals(token, result);
        }

        @Test
        @DisplayName("Should return agent workload token")
        void shouldReturnAgentWorkloadToken() {
            // Given
            String token = "workload-token";
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user-token")
                    .agentWorkloadToken(token)
                    .build();

            // When
            String result = proposal.getAgentWorkloadToken();

            // Then
            assertEquals(token, result);
        }

        @Test
        @DisplayName("Should return device fingerprint")
        void shouldReturnDeviceFingerprint() {
            // Given
            String fingerprint = "device-fp-123";
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user-token")
                    .agentWorkloadToken("workload-token")
                    .deviceFingerprint(fingerprint)
                    .build();

            // When
            String result = proposal.getDeviceFingerprint();

            // Then
            assertEquals(fingerprint, result);
        }

        @Test
        @DisplayName("Should return null for missing device fingerprint")
        void shouldReturnNullForMissingDeviceFingerprint() {
            // Given
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("user-token")
                    .agentWorkloadToken("workload-token")
                    .build();

            // When
            String result = proposal.getDeviceFingerprint();

            // Then
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            AgentUserBindingProposal proposal1 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .deviceFingerprint("fp1")
                    .build();

            AgentUserBindingProposal proposal2 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .deviceFingerprint("fp1")
                    .build();

            // Then
            assertEquals(proposal1, proposal2);
            assertEquals(proposal1.hashCode(), proposal2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when optional fields are null")
        void shouldBeEqualWhenOptionalFieldsAreNull() {
            // Given
            AgentUserBindingProposal proposal1 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            AgentUserBindingProposal proposal2 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            // Then
            assertEquals(proposal1, proposal2);
            assertEquals(proposal1.hashCode(), proposal2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when user identity token differs")
        void shouldNotBeEqualWhenUserIdentityTokenDiffers() {
            // Given
            AgentUserBindingProposal proposal1 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            AgentUserBindingProposal proposal2 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token3")
                    .agentWorkloadToken("token2")
                    .build();

            // Then
            assertNotEquals(proposal1, proposal2);
        }

        @Test
        @DisplayName("Should not be equal when agent workload token differs")
        void shouldNotBeEqualWhenAgentWorkloadTokenDiffers() {
            // Given
            AgentUserBindingProposal proposal1 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            AgentUserBindingProposal proposal2 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token3")
                    .build();

            // Then
            assertNotEquals(proposal1, proposal2);
        }

        @Test
        @DisplayName("Should not be equal when device fingerprint differs")
        void shouldNotBeEqualWhenDeviceFingerprintDiffers() {
            // Given
            AgentUserBindingProposal proposal1 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .deviceFingerprint("fp1")
                    .build();

            AgentUserBindingProposal proposal2 = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .deviceFingerprint("fp2")
                    .build();

            // Then
            assertNotEquals(proposal1, proposal2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .deviceFingerprint("fp1")
                    .build();

            // Then
            assertEquals(proposal, proposal);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            // Then
            assertNotEquals(proposal, null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            // Then
            assertNotEquals(proposal, "string");
        }

        @Test
        @DisplayName("Should have consistent hash code")
        void shouldHaveConsistentHashCode() {
            // Given
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .deviceFingerprint("fp1")
                    .build();

            // When
            int hashCode1 = proposal.hashCode();
            int hashCode2 = proposal.hashCode();

            // Then
            assertEquals(hashCode1, hashCode2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // Given
            String userIdentityToken = "token1";
            String agentWorkloadToken = "token2";
            String deviceFingerprint = "fp1";

            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(userIdentityToken)
                    .agentWorkloadToken(agentWorkloadToken)
                    .deviceFingerprint(deviceFingerprint)
                    .build();

            // When
            String result = proposal.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("AgentUserBindingProposal"));
            assertTrue(result.contains(userIdentityToken));
            assertTrue(result.contains(agentWorkloadToken));
            assertTrue(result.contains(deviceFingerprint));
        }

        @Test
        @DisplayName("Should include only required fields in toString when optional is null")
        void shouldIncludeOnlyRequiredFieldsInToStringWhenOptionalIsNull() {
            // Given
            AgentUserBindingProposal proposal = AgentUserBindingProposal.builder()
                    .userIdentityToken("token1")
                    .agentWorkloadToken("token2")
                    .build();

            // When
            String result = proposal.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("AgentUserBindingProposal"));
            assertTrue(result.contains("token1"));
            assertTrue(result.contains("token2"));
        }
    }

    @Nested
    @DisplayName("Jackson Deserialization Tests")
    class JacksonDeserializationTests {

        @Test
        @DisplayName("Should handle null values in deserialization")
        void shouldHandleNullValuesInDeserialization() {
            // When
            AgentUserBindingProposal proposal = new AgentUserBindingProposal(
                    null,
                    null,
                    null
            );

            // Then
            assertNotNull(proposal);
            assertNull(proposal.getUserIdentityToken());
            assertNull(proposal.getAgentWorkloadToken());
            assertNull(proposal.getDeviceFingerprint());
        }

        @Test
        @DisplayName("Should handle partial null values in deserialization")
        void shouldHandlePartialNullValuesInDeserialization() {
            // When
            AgentUserBindingProposal proposal = new AgentUserBindingProposal(
                    "token1",
                    null,
                    "fp1"
            );

            // Then
            assertNotNull(proposal);
            assertEquals("token1", proposal.getUserIdentityToken());
            assertNull(proposal.getAgentWorkloadToken());
            assertEquals("fp1", proposal.getDeviceFingerprint());
        }
    }
}
