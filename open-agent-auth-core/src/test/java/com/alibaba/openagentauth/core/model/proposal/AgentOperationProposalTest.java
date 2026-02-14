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
 * Unit tests for {@link AgentOperationProposal}.
 * <p>
 * This test class validates the behavior of the AgentOperationProposal class,
 * which represents a proposal for agent operation authorization with a Rego policy.
 * </p>
 */
@DisplayName("AgentOperationProposal Tests")
class AgentOperationProposalTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build proposal with policy")
        void shouldBuildProposalWithPolicy() {
            // Given
            String policy = "package auth\nallow { input.user == input.owner }";

            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(policy, proposal.getPolicy());
        }

        @Test
        @DisplayName("Should build proposal with null policy")
        void shouldBuildProposalWithNullPolicy() {
            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(null)
                    .build();

            // Then
            assertNotNull(proposal);
            assertNull(proposal.getPolicy());
        }

        @Test
        @DisplayName("Should build proposal with empty policy")
        void shouldBuildProposalWithEmptyPolicy() {
            // Given
            String policy = "";

            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(policy, proposal.getPolicy());
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            // Given
            String policy = "package auth\nallow { true }";

            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(policy, proposal.getPolicy());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return policy")
        void shouldReturnPolicy() {
            // Given
            String policy = "package auth\ndefault allow = false";
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // When
            String result = proposal.getPolicy();

            // Then
            assertEquals(policy, result);
        }

        @Test
        @DisplayName("Should return null for missing policy")
        void shouldReturnNullForMissingPolicy() {
            // Given
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .build();

            // When
            String result = proposal.getPolicy();

            // Then
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when policies match")
        void shouldBeEqualWhenPoliciesMatch() {
            // Given
            String policy = "package auth\nallow { true }";
            AgentOperationProposal proposal1 = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            AgentOperationProposal proposal2 = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertEquals(proposal1, proposal2);
            assertEquals(proposal1.hashCode(), proposal2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when both policies are null")
        void shouldBeEqualWhenBothPoliciesAreNull() {
            // Given
            AgentOperationProposal proposal1 = AgentOperationProposal.builder()
                    .policy(null)
                    .build();

            AgentOperationProposal proposal2 = AgentOperationProposal.builder()
                    .policy(null)
                    .build();

            // Then
            assertEquals(proposal1, proposal2);
            assertEquals(proposal1.hashCode(), proposal2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when both policies are empty")
        void shouldBeEqualWhenBothPoliciesAreEmpty() {
            // Given
            AgentOperationProposal proposal1 = AgentOperationProposal.builder()
                    .policy("")
                    .build();

            AgentOperationProposal proposal2 = AgentOperationProposal.builder()
                    .policy("")
                    .build();

            // Then
            assertEquals(proposal1, proposal2);
            assertEquals(proposal1.hashCode(), proposal2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when policies differ")
        void shouldNotBeEqualWhenPoliciesDiffer() {
            // Given
            AgentOperationProposal proposal1 = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();

            AgentOperationProposal proposal2 = AgentOperationProposal.builder()
                    .policy("package auth\nallow { false }")
                    .build();

            // Then
            assertNotEquals(proposal1, proposal2);
        }

        @Test
        @DisplayName("Should not be equal when one policy is null")
        void shouldNotBeEqualWhenOnePolicyIsNull() {
            // Given
            AgentOperationProposal proposal1 = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();

            AgentOperationProposal proposal2 = AgentOperationProposal.builder()
                    .policy(null)
                    .build();

            // Then
            assertNotEquals(proposal1, proposal2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();

            // Then
            assertEquals(proposal, proposal);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();

            // Then
            assertNotEquals(proposal, null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy("package auth\nallow { true }")
                    .build();

            // Then
            assertNotEquals(proposal, "string");
        }

        @Test
        @DisplayName("Should have consistent hash code")
        void shouldHaveConsistentHashCode() {
            // Given
            String policy = "package auth\nallow { true }";
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
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
        @DisplayName("Should include policy in toString")
        void shouldIncludePolicyInToString() {
            // Given
            String policy = "package auth\nallow { true }";
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // When
            String result = proposal.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("AgentOperationProposal"));
            assertTrue(result.contains(policy));
        }

        @Test
        @DisplayName("Should include null in toString when policy is null")
        void shouldIncludeNullInToStringWhenPolicyIsNull() {
            // Given
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(null)
                    .build();

            // When
            String result = proposal.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("AgentOperationProposal"));
        }

        @Test
        @DisplayName("Should include empty string in toString when policy is empty")
        void shouldIncludeEmptyStringInToStringWhenPolicyIsEmpty() {
            // Given
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy("")
                    .build();

            // When
            String result = proposal.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("AgentOperationProposal"));
        }
    }

    @Nested
    @DisplayName("Rego Policy Examples Tests")
    class RegoPolicyExamplesTests {

        @Test
        @DisplayName("Should handle simple allow policy")
        void shouldHandleSimpleAllowPolicy() {
            // Given
            String policy = """
                    package auth
                    allow {
                        input.user == input.owner
                    }
                    """;

            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(policy, proposal.getPolicy());
        }

        @Test
        @DisplayName("Should handle complex policy with multiple rules")
        void shouldHandleComplexPolicyWithMultipleRules() {
            // Given
            String policy = """
                    package auth
                    
                    default allow = false
                    
                    allow {
                        input.user == input.owner
                        input.action == "read"
                    }
                    
                    allow {
                        input.user == "admin"
                        input.action == "write"
                    }
                    """;

            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(policy, proposal.getPolicy());
        }

        @Test
        @DisplayName("Should handle policy with time-based restrictions")
        void shouldHandlePolicyWithTimeBasedRestrictions() {
            // Given
            String policy = """
                    package auth
                    import time
                    
                    allow {
                        input.user == input.owner
                        time.now_ns() < input.deadline
                    }
                    """;

            // When
            AgentOperationProposal proposal = AgentOperationProposal.builder()
                    .policy(policy)
                    .build();

            // Then
            assertNotNull(proposal);
            assertEquals(policy, proposal.getPolicy());
        }
    }
}
