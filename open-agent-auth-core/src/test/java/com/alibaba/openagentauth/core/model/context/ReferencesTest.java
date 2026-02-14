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
package com.alibaba.openagentauth.core.model.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link References}.
 * <p>
 * This test class validates the behavior of the References class,
 * which represents references to related proposals or resources.
 * </p>
 */
@DisplayName("References Tests")
class ReferencesTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build references with related proposal ID")
        void shouldBuildReferencesWithRelatedProposalId() {
            // Given
            String relatedProposalId = "proposal-123";

            // When
            References references = References.builder()
                    .relatedProposalId(relatedProposalId)
                    .build();

            // Then
            assertNotNull(references);
            assertEquals(relatedProposalId, references.getRelatedProposalId());
        }

        @Test
        @DisplayName("Should build references without related proposal ID")
        void shouldBuildReferencesWithoutRelatedProposalId() {
            // When
            References references = References.builder()
                    .build();

            // Then
            assertNotNull(references);
            assertNull(references.getRelatedProposalId());
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            // Given
            String relatedProposalId = "proposal-456";

            // When
            References references = References.builder()
                    .relatedProposalId(relatedProposalId)
                    .build();

            // Then
            assertNotNull(references);
            assertEquals(relatedProposalId, references.getRelatedProposalId());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return related proposal ID")
        void shouldReturnRelatedProposalId() {
            // Given
            String relatedProposalId = "proposal-789";
            References references = References.builder()
                    .relatedProposalId(relatedProposalId)
                    .build();

            // When
            String result = references.getRelatedProposalId();

            // Then
            assertEquals(relatedProposalId, result);
        }

        @Test
        @DisplayName("Should return null for missing related proposal ID")
        void shouldReturnNullForMissingRelatedProposalId() {
            // Given
            References references = References.builder()
                    .build();

            // When
            String result = references.getRelatedProposalId();

            // Then
            assertNull(result);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when related proposal IDs match")
        void shouldBeEqualWhenRelatedProposalIdsMatch() {
            // Given
            References references1 = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            References references2 = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            // Then
            assertEquals(references1, references2);
            assertEquals(references1.hashCode(), references2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when both related proposal IDs are null")
        void shouldBeEqualWhenBothRelatedProposalIdsAreNull() {
            // Given
            References references1 = References.builder()
                    .build();

            References references2 = References.builder()
                    .build();

            // Then
            assertEquals(references1, references2);
            assertEquals(references1.hashCode(), references2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when related proposal IDs differ")
        void shouldNotBeEqualWhenRelatedProposalIdsDiffer() {
            // Given
            References references1 = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            References references2 = References.builder()
                    .relatedProposalId("proposal-002")
                    .build();

            // Then
            assertNotEquals(references1, references2);
        }

        @Test
        @DisplayName("Should not be equal when one related proposal ID is null")
        void shouldNotBeEqualWhenOneRelatedProposalIdIsNull() {
            // Given
            References references1 = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            References references2 = References.builder()
                    .build();

            // Then
            assertNotEquals(references1, references2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            References references = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            // Then
            assertEquals(references, references);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            References references = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            // Then
            assertNotEquals(references, null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            References references = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            // Then
            assertNotEquals(references, "string");
        }

        @Test
        @DisplayName("Should have consistent hash code")
        void shouldHaveConsistentHashCode() {
            // Given
            References references = References.builder()
                    .relatedProposalId("proposal-001")
                    .build();

            // When
            int hashCode1 = references.hashCode();
            int hashCode2 = references.hashCode();

            // Then
            assertEquals(hashCode1, hashCode2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include related proposal ID in toString")
        void shouldIncludeRelatedProposalIdInToString() {
            // Given
            String relatedProposalId = "proposal-xyz";
            References references = References.builder()
                    .relatedProposalId(relatedProposalId)
                    .build();

            // When
            String result = references.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("References"));
            assertTrue(result.contains(relatedProposalId));
        }

        @Test
        @DisplayName("Should handle null in toString when related proposal ID is null")
        void shouldHandleNullInToStringWhenRelatedProposalIdIsNull() {
            // Given
            References references = References.builder()
                    .build();

            // When
            String result = references.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("References"));
        }
    }
}
