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
 * Unit tests for {@link AgentIdentity}.
 * <p>
 * Tests the Agent Identity model's behavior including:
 * <ul>
 *   <li>Building identities with all required and optional fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Equals, hashCode, and toString methods</li>
 *   <li>Builder pattern with validation</li>
 *   <li>IssuedFor inner class</li>
 *   <li>Default version behavior</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AgentIdentity Tests")
class AgentIdentityTest {

    private static final String VERSION = "1.0";
    private static final String AGENT_ID = "agent-123";
    private static final String ISSUER = "https://issuer.example.com";
    private static final String ISSUED_TO = "https://issued-to.example.com|user-123";
    private static final Instant NOW = Instant.now();

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build identity with all fields")
        void shouldBuildIdentityWithAllFields() {
            // Given
            AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder()
                    .platform("cloud-platform")
                    .client("web-app")
                    .clientInstance("instance-1")
                    .build();

            // When
            AgentIdentity identity = AgentIdentity.builder()
                    .version(VERSION)
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .issuedFor(issuedFor)
                    .issuanceDate(NOW)
                    .validFrom(NOW)
                    .expires(NOW.plusSeconds(3600))
                    .build();

            // Then
            assertThat(identity).isNotNull();
            assertThat(identity.getVersion()).isEqualTo(VERSION);
            assertThat(identity.getId()).isEqualTo(AGENT_ID);
            assertThat(identity.getIssuer()).isEqualTo(ISSUER);
            assertThat(identity.getIssuedTo()).isEqualTo(ISSUED_TO);
            assertThat(identity.getIssuedFor()).isNotNull();
            assertThat(identity.getIssuedFor().getPlatform()).isEqualTo("cloud-platform");
            assertThat(identity.getIssuedFor().getClient()).isEqualTo("web-app");
            assertThat(identity.getIssuedFor().getClientInstance()).isEqualTo("instance-1");
            assertThat(identity.getIssuanceDate()).isEqualTo(NOW);
            assertThat(identity.getValidFrom()).isEqualTo(NOW);
            assertThat(identity.getExpires()).isEqualTo(NOW.plusSeconds(3600));
        }

        @Test
        @DisplayName("Should build identity with default version")
        void shouldBuildIdentityWithDefaultVersion() {
            // When
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // Then
            assertThat(identity.getVersion()).isEqualTo("1.0");
        }

        @Test
        @DisplayName("Should build identity with null optional fields")
        void shouldBuildIdentityWithNullOptionalFields() {
            // When
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // Then
            assertThat(identity.getIssuedFor()).isNull();
            assertThat(identity.getIssuanceDate()).isNull();
            assertThat(identity.getValidFrom()).isNull();
            assertThat(identity.getExpires()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct version")
        void shouldReturnCorrectVersion() {
            // Given
            AgentIdentity identity = AgentIdentity.builder()
                    .version("2.0")
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity.getVersion()).isEqualTo("2.0");
        }

        @Test
        @DisplayName("Should return correct id")
        void shouldReturnCorrectId() {
            // Given
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity.getId()).isEqualTo(AGENT_ID);
        }

        @Test
        @DisplayName("Should return correct issuer")
        void shouldReturnCorrectIssuer() {
            // Given
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity.getIssuer()).isEqualTo(ISSUER);
        }

        @Test
        @DisplayName("Should return correct issuedTo")
        void shouldReturnCorrectIssuedTo() {
            // Given
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity.getIssuedTo()).isEqualTo(ISSUED_TO);
        }

        @Test
        @DisplayName("Should return correct issuedFor")
        void shouldReturnCorrectIssuedFor() {
            // Given
            AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder()
                    .platform("platform-1")
                    .build();
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .issuedFor(issuedFor)
                    .build();

            // When & Then
            assertThat(identity.getIssuedFor()).isNotNull();
            assertThat(identity.getIssuedFor().getPlatform()).isEqualTo("platform-1");
        }

        @Test
        @DisplayName("Should return correct issuanceDate")
        void shouldReturnCorrectIssuanceDate() {
            // Given
            Instant issuanceDate = NOW.minusSeconds(100);
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .issuanceDate(issuanceDate)
                    .build();

            // When & Then
            assertThat(identity.getIssuanceDate()).isEqualTo(issuanceDate);
        }

        @Test
        @DisplayName("Should return correct validFrom")
        void shouldReturnCorrectValidFrom() {
            // Given
            Instant validFrom = NOW;
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .validFrom(validFrom)
                    .build();

            // When & Then
            assertThat(identity.getValidFrom()).isEqualTo(validFrom);
        }

        @Test
        @DisplayName("Should return correct expires")
        void shouldReturnCorrectExpires() {
            // Given
            Instant expires = NOW.plusSeconds(7200);
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .expires(expires)
                    .build();

            // When & Then
            assertThat(identity.getExpires()).isEqualTo(expires);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = createTestIdentity();

            // When & Then
            assertThat(identity1).isEqualTo(identity2);
            assertThat(identity1.hashCode()).isEqualTo(identity2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when version differs")
        void shouldNotBeEqualWhenVersionDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .version("2.0")
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when id differs")
        void shouldNotBeEqualWhenIdDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id("different-id")
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when issuer differs")
        void shouldNotBeEqualWhenIssuerDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer("https://different-issuer.com")
                    .issuedTo(ISSUED_TO)
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when issuedTo differs")
        void shouldNotBeEqualWhenIssuedToDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo("https://different-issued-to.com|user-456")
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when issuedFor differs")
        void shouldNotBeEqualWhenIssuedForDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .issuedFor(AgentIdentity.IssuedFor.builder()
                            .platform("different-platform")
                            .build())
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when issuanceDate differs")
        void shouldNotBeEqualWhenIssuanceDateDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .issuanceDate(NOW.plusSeconds(100))
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when validFrom differs")
        void shouldNotBeEqualWhenValidFromDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .validFrom(NOW.plusSeconds(100))
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should not be equal when expires differs")
        void shouldNotBeEqualWhenExpiresDiffers() {
            // Given
            AgentIdentity identity1 = createTestIdentity();
            AgentIdentity identity2 = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .expires(NOW.plusSeconds(7200))
                    .build();

            // When & Then
            assertThat(identity1).isNotEqualTo(identity2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            AgentIdentity identity = createTestIdentity();

            // When & Then
            assertThat(identity).isEqualTo(identity);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            AgentIdentity identity = createTestIdentity();

            // When & Then
            assertThat(identity).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            AgentIdentity identity = createTestIdentity();

            // When & Then
            assertThat(identity).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should contain all fields in toString")
        void shouldContainAllFieldsInToString() {
            // Given
            AgentIdentity identity = createTestIdentity();

            // When
            String toString = identity.toString();

            // Then
            assertThat(toString).contains("AgentIdentity");
            assertThat(toString).contains("version='1.0'");
            assertThat(toString).contains("id='agent-123'");
            assertThat(toString).contains("issuer='https://issuer.example.com'");
            assertThat(toString).contains("issuedTo='https://issued-to.example.com|user-123'");
        }

        @Test
        @DisplayName("Should handle null fields in toString")
        void shouldHandleNullFieldsInToString() {
            // Given
            AgentIdentity identity = AgentIdentity.builder()
                    .id(AGENT_ID)
                    .issuer(ISSUER)
                    .issuedTo(ISSUED_TO)
                    .build();

            // When
            String toString = identity.toString();

            // Then
            assertThat(toString).isNotNull();
            assertThat(toString).contains("AgentIdentity");
        }
    }

    @Nested
    @DisplayName("IssuedFor Tests")
    class IssuedForTests {

        @Test
        @DisplayName("Should build IssuedFor with all fields")
        void shouldBuildIssuedForWithAllFields() {
            // When
            AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder()
                    .platform("platform-1")
                    .client("client-1")
                    .clientInstance("instance-1")
                    .build();

            // Then
            assertThat(issuedFor.getPlatform()).isEqualTo("platform-1");
            assertThat(issuedFor.getClient()).isEqualTo("client-1");
            assertThat(issuedFor.getClientInstance()).isEqualTo("instance-1");
        }

        @Test
        @DisplayName("Should build IssuedFor with null fields")
        void shouldBuildIssuedForWithNullFields() {
            // When
            AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder().build();

            // Then
            assertThat(issuedFor.getPlatform()).isNull();
            assertThat(issuedFor.getClient()).isNull();
            assertThat(issuedFor.getClientInstance()).isNull();
        }

        @Test
        @DisplayName("IssuedFor should be equal when all fields match")
        void issuedForShouldBeEqualWhenAllFieldsMatch() {
            // Given
            AgentIdentity.IssuedFor issuedFor1 = AgentIdentity.IssuedFor.builder()
                    .platform("platform-1")
                    .client("client-1")
                    .clientInstance("instance-1")
                    .build();
            AgentIdentity.IssuedFor issuedFor2 = AgentIdentity.IssuedFor.builder()
                    .platform("platform-1")
                    .client("client-1")
                    .clientInstance("instance-1")
                    .build();

            // When & Then
            assertThat(issuedFor1).isEqualTo(issuedFor2);
            assertThat(issuedFor1.hashCode()).isEqualTo(issuedFor2.hashCode());
        }

        @Test
        @DisplayName("IssuedFor should have correct toString")
        void issuedForShouldHaveCorrectToString() {
            // Given
            AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder()
                    .platform("platform-1")
                    .client("client-1")
                    .clientInstance("instance-1")
                    .build();

            // When
            String toString = issuedFor.toString();

            // Then
            assertThat(toString).contains("IssuedFor");
            assertThat(toString).contains("platform='platform-1'");
            assertThat(toString).contains("client='client-1'");
            assertThat(toString).contains("clientInstance='instance-1'");
        }
    }

    /**
     * Helper method to create a test AgentIdentity instance.
     *
     * @return a test AgentIdentity instance
     */
    private AgentIdentity createTestIdentity() {
        AgentIdentity.IssuedFor issuedFor = AgentIdentity.IssuedFor.builder()
                .platform("cloud-platform")
                .client("web-app")
                .clientInstance("instance-1")
                .build();

        return AgentIdentity.builder()
                .version(VERSION)
                .id(AGENT_ID)
                .issuer(ISSUER)
                .issuedTo(ISSUED_TO)
                .issuedFor(issuedFor)
                .issuanceDate(NOW)
                .validFrom(NOW)
                .expires(NOW.plusSeconds(3600))
                .build();
    }
}
