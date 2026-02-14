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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TrustDomain}.
 */
@DisplayName("TrustDomain Tests")
class TrustDomainTest {

    private static final String VALID_DOMAIN_ID = "wimse://example.com";
    private static final String DOMAIN_NAME = "example.com";

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create trust domain with valid domain ID")
        void shouldCreateTrustDomainWithValidDomainId() {
            // Act
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            // Assert
            assertThat(domain).isNotNull();
            assertThat(domain.getDomainId()).isEqualTo(VALID_DOMAIN_ID);
        }

        @Test
        @DisplayName("Should create trust domain without wimse:// prefix")
        void shouldCreateTrustDomainWithoutPrefix() {
            // Act
            TrustDomain domain = new TrustDomain(DOMAIN_NAME);

            // Assert
            assertThat(domain).isNotNull();
            assertThat(domain.getDomainId()).isEqualTo(DOMAIN_NAME);
        }

        @Test
        @DisplayName("Should throw exception when domain ID is null")
        void shouldThrowExceptionWhenDomainIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new TrustDomain(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Domain ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when domain ID is empty")
        void shouldThrowExceptionWhenDomainIdIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> new TrustDomain(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Domain ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when domain ID is whitespace")
        void shouldThrowExceptionWhenDomainIdIsWhitespace() {
            // Act & Assert
            assertThatThrownBy(() -> new TrustDomain("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Domain ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("getDomainName")
    class GetDomainNameTests {

        @Test
        @DisplayName("Should extract domain name from wimse:// prefixed domain ID")
        void shouldExtractDomainNameFromPrefixedDomainId() {
            // Arrange
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            // Act
            String domainName = domain.getDomainName();

            // Assert
            assertThat(domainName).isEqualTo(DOMAIN_NAME);
        }

        @Test
        @DisplayName("Should return domain ID when it has no wimse:// prefix")
        void shouldReturnDomainIdWhenNoPrefix() {
            // Arrange
            TrustDomain domain = new TrustDomain(DOMAIN_NAME);

            // Act
            String domainName = domain.getDomainName();

            // Assert
            assertThat(domainName).isEqualTo(DOMAIN_NAME);
        }
    }

    @Nested
    @DisplayName("equals and hashCode")
    class EqualityTests {

        @Test
        @DisplayName("Should be equal when domain IDs are same")
        void shouldBeEqualWhenDomainIdsAreSame() {
            // Arrange
            TrustDomain domain1 = new TrustDomain(VALID_DOMAIN_ID);
            TrustDomain domain2 = new TrustDomain(VALID_DOMAIN_ID);

            // Act & Assert
            assertThat(domain1).isEqualTo(domain2);
            assertThat(domain1.hashCode()).isEqualTo(domain2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when domain IDs are different")
        void shouldNotBeEqualWhenDomainIdsAreDifferent() {
            // Arrange
            TrustDomain domain1 = new TrustDomain("wimse://example.com");
            TrustDomain domain2 = new TrustDomain("wimse://other.com");

            // Act & Assert
            assertThat(domain1).isNotEqualTo(domain2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Arrange
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            // Act & Assert
            assertThat(domain).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Arrange
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            // Act & Assert
            assertThat(domain).isNotEqualTo("string");
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Arrange
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            // Act & Assert
            assertThat(domain).isEqualTo(domain);
        }
    }

    @Nested
    @DisplayName("toString")
    class ToStringTests {

        @Test
        @DisplayName("Should contain domain ID in toString")
        void shouldContainDomainIdInToString() {
            // Arrange
            TrustDomain domain = new TrustDomain(VALID_DOMAIN_ID);

            // Act
            String result = domain.toString();

            // Assert
            assertThat(result).contains(VALID_DOMAIN_ID);
        }
    }
}
