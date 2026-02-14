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
package com.alibaba.openagentauth.core.model.identity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link DelegationChain}.
 * <p>
 * Tests the Delegation Chain model's behavior including:
 * <ul>
 *   <li>Building delegation chains with all required and optional fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Equals, hashCode, and toString methods</li>
 *   <li>Builder pattern</li>
 *   <li>Relationship with AgentIdentity</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("DelegationChain Tests")
class DelegationChainTest {

    private static final String DELEGATOR_JTI = "delegator-jti-123";
    private static final String AS_SIGNATURE = "as-signature-abc123";
    private static final Instant NOW = Instant.now();

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build delegation chain with all fields")
        void shouldBuildDelegationChainWithAllFields() {
            // Given
            AgentIdentity delegatorIdentity = createTestAgentIdentity();

            // When
            DelegationChain delegationChain = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(delegatorIdentity)
                    .delegationTimestamp(NOW)
                    .operationSummary("Query user data")
                    .asSignature(AS_SIGNATURE)
                    .build();

            // Then
            assertThat(delegationChain).isNotNull();
            assertThat(delegationChain.getDelegatorJti()).isEqualTo(DELEGATOR_JTI);
            assertThat(delegationChain.getDelegatorAgentIdentity()).isNotNull();
            assertThat(delegationChain.getDelegatorAgentIdentity().getId()).isEqualTo("agent-123");
            assertThat(delegationChain.getDelegationTimestamp()).isEqualTo(NOW);
            assertThat(delegationChain.getOperationSummary()).isEqualTo("Query user data");
            assertThat(delegationChain.getAsSignature()).isEqualTo(AS_SIGNATURE);
        }

        @Test
        @DisplayName("Should build delegation chain with null optional fields")
        void shouldBuildDelegationChainWithNullOptionalFields() {
            // Given
            AgentIdentity delegatorIdentity = createTestAgentIdentity();

            // When
            DelegationChain delegationChain = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(delegatorIdentity)
                    .delegationTimestamp(NOW)
                    .asSignature(AS_SIGNATURE)
                    .build();

            // Then
            assertThat(delegationChain).isNotNull();
            assertThat(delegationChain.getOperationSummary()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct delegatorJti")
        void shouldReturnCorrectDelegatorJti() {
            // Given
            DelegationChain delegationChain = createTestDelegationChain();

            // When & Then
            assertThat(delegationChain.getDelegatorJti()).isEqualTo(DELEGATOR_JTI);
        }

        @Test
        @DisplayName("Should return correct delegatorAgentIdentity")
        void shouldReturnCorrectDelegatorAgentIdentity() {
            // Given
            DelegationChain delegationChain = createTestDelegationChain();

            // When & Then
            assertThat(delegationChain.getDelegatorAgentIdentity()).isNotNull();
            assertThat(delegationChain.getDelegatorAgentIdentity().getId()).isEqualTo("agent-123");
            assertThat(delegationChain.getDelegatorAgentIdentity().getIssuer()).isEqualTo("https://issuer.example.com");
        }

        @Test
        @DisplayName("Should return correct delegationTimestamp")
        void shouldReturnCorrectDelegationTimestamp() {
            // Given
            Instant timestamp = NOW.minusSeconds(100);
            DelegationChain delegationChain = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(createTestAgentIdentity())
                    .delegationTimestamp(timestamp)
                    .asSignature(AS_SIGNATURE)
                    .build();

            // When & Then
            assertThat(delegationChain.getDelegationTimestamp()).isEqualTo(timestamp);
        }

        @Test
        @DisplayName("Should return correct operationSummary")
        void shouldReturnCorrectOperationSummary() {
            // Given
            DelegationChain delegationChain = createTestDelegationChain();

            // When & Then
            assertThat(delegationChain.getOperationSummary()).isEqualTo("Query user data");
        }

        @Test
        @DisplayName("Should return correct asSignature")
        void shouldReturnCorrectAsSignature() {
            // Given
            DelegationChain delegationChain = createTestDelegationChain();

            // When & Then
            assertThat(delegationChain.getAsSignature()).isEqualTo(AS_SIGNATURE);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            DelegationChain chain1 = createTestDelegationChain();
            DelegationChain chain2 = createTestDelegationChain();

            // When & Then
            assertThat(chain1).isEqualTo(chain2);
            assertThat(chain1.hashCode()).isEqualTo(chain2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when delegatorJti differs")
        void shouldNotBeEqualWhenDelegatorJtiDiffers() {
            // Given
            DelegationChain chain1 = createTestDelegationChain();
            DelegationChain chain2 = DelegationChain.builder()
                    .delegatorJti("different-jti")
                    .delegatorAgentIdentity(createTestAgentIdentity())
                    .delegationTimestamp(NOW)
                    .asSignature(AS_SIGNATURE)
                    .build();

            // When & Then
            assertThat(chain1).isNotEqualTo(chain2);
        }

        @Test
        @DisplayName("Should not be equal when delegatorAgentIdentity differs")
        void shouldNotBeEqualWhenDelegatorAgentIdentityDiffers() {
            // Given
            DelegationChain chain1 = createTestDelegationChain();
            AgentIdentity differentIdentity = AgentIdentity.builder()
                    .id("different-agent")
                    .issuer("https://issuer.example.com")
                    .issuedTo("https://issued-to.example.com|user-123")
                    .build();
            DelegationChain chain2 = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(differentIdentity)
                    .delegationTimestamp(NOW)
                    .asSignature(AS_SIGNATURE)
                    .build();

            // When & Then
            assertThat(chain1).isNotEqualTo(chain2);
        }

        @Test
        @DisplayName("Should not be equal when delegationTimestamp differs")
        void shouldNotBeEqualWhenDelegationTimestampDiffers() {
            // Given
            DelegationChain chain1 = createTestDelegationChain();
            DelegationChain chain2 = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(createTestAgentIdentity())
                    .delegationTimestamp(NOW.plusSeconds(100))
                    .asSignature(AS_SIGNATURE)
                    .build();

            // When & Then
            assertThat(chain1).isNotEqualTo(chain2);
        }

        @Test
        @DisplayName("Should not be equal when operationSummary differs")
        void shouldNotBeEqualWhenOperationSummaryDiffers() {
            // Given
            DelegationChain chain1 = createTestDelegationChain();
            DelegationChain chain2 = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(createTestAgentIdentity())
                    .delegationTimestamp(NOW)
                    .operationSummary("Different operation")
                    .asSignature(AS_SIGNATURE)
                    .build();

            // When & Then
            assertThat(chain1).isNotEqualTo(chain2);
        }

        @Test
        @DisplayName("Should not be equal when asSignature differs")
        void shouldNotBeEqualWhenAsSignatureDiffers() {
            // Given
            DelegationChain chain1 = createTestDelegationChain();
            DelegationChain chain2 = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(createTestAgentIdentity())
                    .delegationTimestamp(NOW)
                    .operationSummary("Query user data")
                    .asSignature("different-signature")
                    .build();

            // When & Then
            assertThat(chain1).isNotEqualTo(chain2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            DelegationChain chain = createTestDelegationChain();

            // When & Then
            assertThat(chain).isEqualTo(chain);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            DelegationChain chain = createTestDelegationChain();

            // When & Then
            assertThat(chain).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            DelegationChain chain = createTestDelegationChain();

            // When & Then
            assertThat(chain).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should contain all fields in toString")
        void shouldContainAllFieldsInToString() {
            // Given
            DelegationChain delegationChain = createTestDelegationChain();

            // When
            String toString = delegationChain.toString();

            // Then
            assertThat(toString).contains("DelegationChain");
            assertThat(toString).contains("delegatorJti='delegator-jti-123'");
            assertThat(toString).contains("delegatorAgentIdentity=");
            assertThat(toString).contains("delegationTimestamp=");
            assertThat(toString).contains("operationSummary='Query user data'");
            assertThat(toString).contains("asSignature='as-signature-abc123'");
        }

        @Test
        @DisplayName("Should handle null operationSummary in toString")
        void shouldHandleNullOperationSummaryInToString() {
            // Given
            DelegationChain delegationChain = DelegationChain.builder()
                    .delegatorJti(DELEGATOR_JTI)
                    .delegatorAgentIdentity(createTestAgentIdentity())
                    .delegationTimestamp(NOW)
                    .asSignature(AS_SIGNATURE)
                    .build();

            // When
            String toString = delegationChain.toString();

            // Then
            assertThat(toString).isNotNull();
            assertThat(toString).contains("DelegationChain");
        }
    }

    /**
     * Helper method to create a test AgentIdentity instance.
     *
     * @return a test AgentIdentity instance
     */
    private AgentIdentity createTestAgentIdentity() {
        return AgentIdentity.builder()
                .id("agent-123")
                .issuer("https://issuer.example.com")
                .issuedTo("https://issued-to.example.com|user-123")
                .build();
    }

    /**
     * Helper method to create a test DelegationChain instance.
     *
     * @return a test DelegationChain instance
     */
    private DelegationChain createTestDelegationChain() {
        return DelegationChain.builder()
                .delegatorJti(DELEGATOR_JTI)
                .delegatorAgentIdentity(createTestAgentIdentity())
                .delegationTimestamp(NOW)
                .operationSummary("Query user data")
                .asSignature(AS_SIGNATURE)
                .build();
    }
}
