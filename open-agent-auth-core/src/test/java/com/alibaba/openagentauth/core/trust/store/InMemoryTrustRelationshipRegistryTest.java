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
package com.alibaba.openagentauth.core.trust.store;

import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.trust.model.TrustRelationship;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryTrustRelationshipRegistry}.
 */
@DisplayName("InMemoryTrustRelationshipRegistry Tests")
class InMemoryTrustRelationshipRegistryTest {

    private InMemoryTrustRelationshipRegistry registry;
    private TrustDomain sourceDomain;
    private TrustDomain targetDomain;

    @BeforeEach
    void setUp() {
        registry = new InMemoryTrustRelationshipRegistry();
        sourceDomain = new TrustDomain("wimse://source.example.com");
        targetDomain = new TrustDomain("wimse://target.example.com");
    }

    @Nested
    @DisplayName("establishRelationship")
    class EstablishRelationshipTests {

        @Test
        @DisplayName("Should establish trust relationship successfully")
        void shouldEstablishTrustRelationshipSuccessfully() {
            // Act
            TrustRelationship relationship = registry.establishRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(relationship).isNotNull();
            assertThat(relationship.getSourceDomain()).isEqualTo(sourceDomain);
            assertThat(relationship.getTargetDomain()).isEqualTo(targetDomain);
            assertThat(relationship.isActive()).isTrue();
        }

        @Test
        @DisplayName("Should overwrite existing relationship with same domains")
        void shouldOverwriteExistingRelationship() {
            // Arrange
            TrustRelationship existing = registry.establishRelationship(sourceDomain, targetDomain);
            existing.deactivate();

            // Act
            TrustRelationship newRelationship = registry.establishRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(newRelationship.isActive()).isTrue();
        }

        @Test
        @DisplayName("Should throw exception when source domain is null")
        void shouldThrowExceptionWhenSourceDomainIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> registry.establishRelationship(null, targetDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Source domain cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when target domain is null")
        void shouldThrowExceptionWhenTargetDomainIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> registry.establishRelationship(sourceDomain, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Target domain cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when both domains are null")
        void shouldThrowExceptionWhenBothDomainsAreNull() {
            // Act & Assert
            assertThatThrownBy(() -> registry.establishRelationship(null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Source domain cannot be null");
        }
    }

    @Nested
    @DisplayName("getRelationship")
    class GetRelationshipTests {

        @Test
        @DisplayName("Should return relationship when found")
        void shouldReturnRelationshipWhenFound() {
            // Arrange
            TrustRelationship established = registry.establishRelationship(sourceDomain, targetDomain);

            // Act
            Optional<TrustRelationship> result = registry.getRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(result).isPresent();
            assertThat(result.get()).isEqualTo(established);
        }

        @Test
        @DisplayName("Should return empty when relationship not found")
        void shouldReturnEmptyWhenRelationshipNotFound() {
            // Act
            Optional<TrustRelationship> result = registry.getRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when source domain is null")
        void shouldReturnEmptyWhenSourceDomainIsNull() {
            // Act
            Optional<TrustRelationship> result = registry.getRelationship(null, targetDomain);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when target domain is null")
        void shouldReturnEmptyWhenTargetDomainIsNull() {
            // Act
            Optional<TrustRelationship> result = registry.getRelationship(sourceDomain, null);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getRelationships")
    class GetRelationshipsTests {

        @Test
        @DisplayName("Should return all relationships for domain as source")
        void shouldReturnAllRelationshipsForDomainAsSource() {
            // Arrange
            TrustDomain target1 = new TrustDomain("wimse://target1.com");
            TrustDomain target2 = new TrustDomain("wimse://target2.com");
            
            registry.establishRelationship(sourceDomain, target1);
            registry.establishRelationship(sourceDomain, target2);

            // Act
            List<TrustRelationship> result = registry.getRelationships(sourceDomain);

            // Assert
            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("Should return all relationships for domain as target")
        void shouldReturnAllRelationshipsForDomainAsTarget() {
            // Arrange
            TrustDomain source1 = new TrustDomain("wimse://source1.com");
            TrustDomain source2 = new TrustDomain("wimse://source2.com");
            
            registry.establishRelationship(source1, targetDomain);
            registry.establishRelationship(source2, targetDomain);

            // Act
            List<TrustRelationship> result = registry.getRelationships(targetDomain);

            // Assert
            assertThat(result).hasSize(2);
        }

        @Test
        @DisplayName("Should return relationships where domain is both source and target")
        void shouldReturnRelationshipsWhereDomainIsBothSourceAndTarget() {
            // Arrange
            TrustDomain otherDomain = new TrustDomain("wimse://other.com");
            
            registry.establishRelationship(sourceDomain, targetDomain);
            registry.establishRelationship(otherDomain, sourceDomain);
            registry.establishRelationship(sourceDomain, otherDomain);

            // Act
            List<TrustRelationship> result = registry.getRelationships(sourceDomain);

            // Assert
            assertThat(result).hasSize(3);
        }

        @Test
        @DisplayName("Should return empty list when no relationships for domain")
        void shouldReturnEmptyListWhenNoRelationshipsForDomain() {
            // Act
            List<TrustRelationship> result = registry.getRelationships(sourceDomain);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list when domain is null")
        void shouldReturnEmptyListWhenDomainIsNull() {
            // Act
            List<TrustRelationship> result = registry.getRelationships(null);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("removeRelationship")
    class RemoveRelationshipTests {

        @Test
        @DisplayName("Should remove relationship successfully")
        void shouldRemoveRelationshipSuccessfully() {
            // Arrange
            registry.establishRelationship(sourceDomain, targetDomain);

            // Act
            registry.removeRelationship(sourceDomain, targetDomain);

            // Assert
            Optional<TrustRelationship> result = registry.getRelationship(sourceDomain, targetDomain);
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should do nothing when relationship not found")
        void shouldDoNothingWhenRelationshipNotFound() {
            // Act & Assert - should not throw exception
            registry.removeRelationship(sourceDomain, targetDomain);
        }

        @Test
        @DisplayName("Should do nothing when source domain is null")
        void shouldDoNothingWhenSourceDomainIsNull() {
            // Act & Assert - should not throw exception
            registry.removeRelationship(null, targetDomain);
        }

        @Test
        @DisplayName("Should do nothing when target domain is null")
        void shouldDoNothingWhenTargetDomainIsNull() {
            // Act & Assert - should not throw exception
            registry.removeRelationship(sourceDomain, null);
        }
    }

    @Nested
    @DisplayName("hasActiveRelationship")
    class HasActiveRelationshipTests {

        @Test
        @DisplayName("Should return true when active relationship exists")
        void shouldReturnTrueWhenActiveRelationshipExists() {
            // Arrange
            registry.establishRelationship(sourceDomain, targetDomain);

            // Act
            boolean result = registry.hasActiveRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false when relationship is deactivated")
        void shouldReturnFalseWhenRelationshipIsDeactivated() {
            // Arrange
            TrustRelationship relationship = registry.establishRelationship(sourceDomain, targetDomain);
            relationship.deactivate();

            // Act
            boolean result = registry.hasActiveRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when relationship not found")
        void shouldReturnFalseWhenRelationshipNotFound() {
            // Act
            boolean result = registry.hasActiveRelationship(sourceDomain, targetDomain);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when source domain is null")
        void shouldReturnFalseWhenSourceDomainIsNull() {
            // Act
            boolean result = registry.hasActiveRelationship(null, targetDomain);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should return false when target domain is null")
        void shouldReturnFalseWhenTargetDomainIsNull() {
            // Act
            boolean result = registry.hasActiveRelationship(sourceDomain, null);

            // Assert
            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("listAllRelationships")
    class ListAllRelationshipsTests {

        @Test
        @DisplayName("Should return all relationships")
        void shouldReturnAllRelationships() {
            // Arrange
            TrustDomain domain1 = new TrustDomain("wimse://domain1.com");
            TrustDomain domain2 = new TrustDomain("wimse://domain2.com");
            
            registry.establishRelationship(sourceDomain, targetDomain);
            registry.establishRelationship(sourceDomain, domain1);
            registry.establishRelationship(domain1, domain2);

            // Act
            List<TrustRelationship> result = registry.listAllRelationships();

            // Assert
            assertThat(result).hasSize(3);
        }

        @Test
        @DisplayName("Should return empty list when no relationships")
        void shouldReturnEmptyListWhenNoRelationships() {
            // Act
            List<TrustRelationship> result = registry.listAllRelationships();

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("clear")
    class ClearTests {

        @Test
        @DisplayName("Should clear all relationships")
        void shouldClearAllRelationships() {
            // Arrange
            TrustDomain domain1 = new TrustDomain("wimse://domain1.com");
            TrustDomain domain2 = new TrustDomain("wimse://domain2.com");
            
            registry.establishRelationship(sourceDomain, targetDomain);
            registry.establishRelationship(sourceDomain, domain1);
            registry.establishRelationship(domain1, domain2);

            // Act
            registry.clear();

            // Assert
            assertThat(registry.listAllRelationships()).isEmpty();
        }

        @Test
        @DisplayName("Should handle clear when registry is empty")
        void shouldHandleClearWhenRegistryIsEmpty() {
            // Act & Assert - should not throw exception
            registry.clear();
        }
    }
}
