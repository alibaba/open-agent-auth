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
package com.alibaba.openagentauth.core.trust.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TrustRelationship}.
 */
@DisplayName("TrustRelationship Tests")
class TrustRelationshipTest {

    private static final String SOURCE_DOMAIN_ID = "wimse://source.example.com";
    private static final String TARGET_DOMAIN_ID = "wimse://target.example.com";

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create trust relationship with valid domains")
        void shouldCreateTrustRelationshipWithValidDomains() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);

            // Act
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(relationship).isNotNull();
            assertThat(relationship.getSourceDomain()).isEqualTo(sourceDomain);
            assertThat(relationship.getTargetDomain()).isEqualTo(targetDomain);
            assertThat(relationship.isActive()).isTrue();
            assertThat(relationship.getEstablishedAt()).isNotNull();
            assertThat(relationship.getEstablishedAt()).isBeforeOrEqualTo(Instant.now());
        }

        @Test
        @DisplayName("Should throw exception when source domain is null")
        void shouldThrowExceptionWhenSourceDomainIsNull() {
            // Arrange
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);

            // Act & Assert
            assertThatThrownBy(() -> new TrustRelationship(null, targetDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Source domain cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when target domain is null")
        void shouldThrowExceptionWhenTargetDomainIsNull() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);

            // Act & Assert
            assertThatThrownBy(() -> new TrustRelationship(sourceDomain, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Target domain cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when both domains are null")
        void shouldThrowExceptionWhenBothDomainsAreNull() {
            // Act & Assert
            assertThatThrownBy(() -> new TrustRelationship(null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Source domain cannot be null");
        }
    }

    @Nested
    @DisplayName("Activation and Deactivation")
    class ActivationTests {

        @Test
        @DisplayName("Should be active by default")
        void shouldBeActiveByDefault() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Act & Assert
            assertThat(relationship.isActive()).isTrue();
        }

        @Test
        @DisplayName("Should deactivate relationship")
        void shouldDeactivateRelationship() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Act
            relationship.deactivate();

            // Assert
            assertThat(relationship.isActive()).isFalse();
        }

        @Test
        @DisplayName("Should activate relationship")
        void shouldActivateRelationship() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);
            relationship.deactivate();

            // Act
            relationship.activate();

            // Assert
            assertThat(relationship.isActive()).isTrue();
        }

        @Test
        @DisplayName("Should set active status")
        void shouldSetActiveStatus() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Act
            relationship.setActive(false);

            // Assert
            assertThat(relationship.isActive()).isFalse();

            // Act
            relationship.setActive(true);

            // Assert
            assertThat(relationship.isActive()).isTrue();
        }
    }

    @Nested
    @DisplayName("equals and hashCode")
    class EqualityTests {

        @Test
        @DisplayName("Should be equal when source and target domains are same")
        void shouldBeEqualWhenDomainsAreSame() {
            // Arrange
            TrustDomain sourceDomain1 = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain1 = new TrustDomain(TARGET_DOMAIN_ID);
            TrustDomain sourceDomain2 = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain2 = new TrustDomain(TARGET_DOMAIN_ID);

            TrustRelationship rel1 = new TrustRelationship(sourceDomain1, targetDomain1);
            TrustRelationship rel2 = new TrustRelationship(sourceDomain2, targetDomain2);

            // Act & Assert
            assertThat(rel1).isEqualTo(rel2);
            assertThat(rel1.hashCode()).isEqualTo(rel2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when source domains are different")
        void shouldNotBeEqualWhenSourceDomainsAreDifferent() {
            // Arrange
            TrustDomain sourceDomain1 = new TrustDomain("wimse://source1.example.com");
            TrustDomain sourceDomain2 = new TrustDomain("wimse://source2.example.com");
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);

            TrustRelationship rel1 = new TrustRelationship(sourceDomain1, targetDomain);
            TrustRelationship rel2 = new TrustRelationship(sourceDomain2, targetDomain);

            // Act & Assert
            assertThat(rel1).isNotEqualTo(rel2);
        }

        @Test
        @DisplayName("Should not be equal when target domains are different")
        void shouldNotBeEqualWhenTargetDomainsAreDifferent() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain1 = new TrustDomain("wimse://target1.example.com");
            TrustDomain targetDomain2 = new TrustDomain("wimse://target2.example.com");

            TrustRelationship rel1 = new TrustRelationship(sourceDomain, targetDomain1);
            TrustRelationship rel2 = new TrustRelationship(sourceDomain, targetDomain2);

            // Act & Assert
            assertThat(rel1).isNotEqualTo(rel2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Act & Assert
            assertThat(relationship).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Act & Assert
            assertThat(relationship).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("toString")
    class ToStringTests {

        @Test
        @DisplayName("Should contain domain IDs in toString")
        void shouldContainDomainIdsInToString() {
            // Arrange
            TrustDomain sourceDomain = new TrustDomain(SOURCE_DOMAIN_ID);
            TrustDomain targetDomain = new TrustDomain(TARGET_DOMAIN_ID);
            TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);

            // Act
            String result = relationship.toString();

            // Assert
            assertThat(result).contains(SOURCE_DOMAIN_ID);
            assertThat(result).contains(TARGET_DOMAIN_ID);
        }
    }
}
