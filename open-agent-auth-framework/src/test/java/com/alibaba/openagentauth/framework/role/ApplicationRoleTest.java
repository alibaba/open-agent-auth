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
package com.alibaba.openagentauth.framework.role;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ApplicationRole}.
 * <p>
 * This test class verifies the behavior of the ApplicationRole enum,
 * including role code retrieval, description retrieval, and role lookup by code.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ApplicationRole Enum Tests")
class ApplicationRoleTest {

    @Nested
    @DisplayName("getCode() Tests")
    class GetCodeTests {

        @Test
        @DisplayName("Should return correct code for AGENT_USER_IDP")
        void shouldReturnCorrectCodeForAgentUserIdp() {
            assertThat(ApplicationRole.AGENT_USER_IDP.getCode())
                .isEqualTo("agent-user-idp");
        }

        @Test
        @DisplayName("Should return correct code for AGENT_IDP")
        void shouldReturnCorrectCodeForAgentIdp() {
            assertThat(ApplicationRole.AGENT_IDP.getCode())
                .isEqualTo("agent-idp");
        }

        @Test
        @DisplayName("Should return correct code for AS_USER_IDP")
        void shouldReturnCorrectCodeForAsUserIdp() {
            assertThat(ApplicationRole.AS_USER_IDP.getCode())
                .isEqualTo("as-user-idp");
        }

        @Test
        @DisplayName("Should return correct code for AUTHORIZATION_SERVER")
        void shouldReturnCorrectCodeForAuthorizationServer() {
            assertThat(ApplicationRole.AUTHORIZATION_SERVER.getCode())
                .isEqualTo("authorization-server");
        }

        @Test
        @DisplayName("Should return correct code for RESOURCE_SERVER")
        void shouldReturnCorrectCodeForResourceServer() {
            assertThat(ApplicationRole.RESOURCE_SERVER.getCode())
                .isEqualTo("resource-server");
        }

        @Test
        @DisplayName("Should return correct code for AGENT")
        void shouldReturnCorrectCodeForAgent() {
            assertThat(ApplicationRole.AGENT.getCode())
                .isEqualTo("agent");
        }
    }

    @Nested
    @DisplayName("getDescription() Tests")
    class GetDescriptionTests {

        @Test
        @DisplayName("Should return correct description for AGENT_USER_IDP")
        void shouldReturnCorrectDescriptionForAgentUserIdp() {
            assertThat(ApplicationRole.AGENT_USER_IDP.getDescription())
                .isEqualTo("Agent User Identity Provider");
        }

        @Test
        @DisplayName("Should return correct description for AGENT_IDP")
        void shouldReturnCorrectDescriptionForAgentIdp() {
            assertThat(ApplicationRole.AGENT_IDP.getDescription())
                .isEqualTo("Agent Identity Provider / WIMSE IDP");
        }

        @Test
        @DisplayName("Should return correct description for AS_USER_IDP")
        void shouldReturnCorrectDescriptionForAsUserIdp() {
            assertThat(ApplicationRole.AS_USER_IDP.getDescription())
                .isEqualTo("Authorization Server User Identity Provider");
        }

        @Test
        @DisplayName("Should return correct description for AUTHORIZATION_SERVER")
        void shouldReturnCorrectDescriptionForAuthorizationServer() {
            assertThat(ApplicationRole.AUTHORIZATION_SERVER.getDescription())
                .isEqualTo("Authorization Server");
        }

        @Test
        @DisplayName("Should return correct description for RESOURCE_SERVER")
        void shouldReturnCorrectDescriptionForResourceServer() {
            assertThat(ApplicationRole.RESOURCE_SERVER.getDescription())
                .isEqualTo("Resource Server");
        }

        @Test
        @DisplayName("Should return correct description for AGENT")
        void shouldReturnCorrectDescriptionForAgent() {
            assertThat(ApplicationRole.AGENT.getDescription())
                .isEqualTo("AI Agent");
        }
    }

    @Nested
    @DisplayName("fromCode() Tests")
    class FromCodeTests {

        @Test
        @DisplayName("Should return AGENT_USER_IDP for 'agent-user-idp'")
        void shouldReturnAgentUserIdpForCode() {
            ApplicationRole role = ApplicationRole.fromCode("agent-user-idp");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.AGENT_USER_IDP);
        }

        @Test
        @DisplayName("Should return AGENT_IDP for 'agent-idp'")
        void shouldReturnAgentIdpForCode() {
            ApplicationRole role = ApplicationRole.fromCode("agent-idp");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.AGENT_IDP);
        }

        @Test
        @DisplayName("Should return AS_USER_IDP for 'as-user-idp'")
        void shouldReturnAsUserIdpForCode() {
            ApplicationRole role = ApplicationRole.fromCode("as-user-idp");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.AS_USER_IDP);
        }

        @Test
        @DisplayName("Should return AUTHORIZATION_SERVER for 'authorization-server'")
        void shouldReturnAuthorizationServerForCode() {
            ApplicationRole role = ApplicationRole.fromCode("authorization-server");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should return RESOURCE_SERVER for 'resource-server'")
        void shouldReturnResourceServerForCode() {
            ApplicationRole role = ApplicationRole.fromCode("resource-server");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.RESOURCE_SERVER);
        }

        @Test
        @DisplayName("Should return AGENT for 'agent'")
        void shouldReturnAgentForCode() {
            ApplicationRole role = ApplicationRole.fromCode("agent");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.AGENT);
        }

        @Test
        @DisplayName("Should return null for invalid code")
        void shouldReturnNullForInvalidCode() {
            ApplicationRole role = ApplicationRole.fromCode("invalid-role");
            assertThat(role).isNull();
        }

        @Test
        @DisplayName("Should return null for empty string")
        void shouldReturnNullForEmptyString() {
            ApplicationRole role = ApplicationRole.fromCode("");
            assertThat(role).isNull();
        }

        @Test
        @DisplayName("Should return null for null input")
        void shouldReturnNullForNullInput() {
            ApplicationRole role = ApplicationRole.fromCode(null);
            assertThat(role).isNull();
        }

        @Test
        @DisplayName("Should be case sensitive")
        void shouldBeCaseSensitive() {
            ApplicationRole role = ApplicationRole.fromCode("AGENT-IDP");
            assertThat(role).isNull();
        }

        @Test
        @DisplayName("Should handle partial matching correctly")
        void shouldHandlePartialMatchingCorrectly() {
            ApplicationRole role = ApplicationRole.fromCode("agent");
            assertThat(role)
                .isNotNull()
                .isEqualTo(ApplicationRole.AGENT);
        }
    }

    @Nested
    @DisplayName("Enum Values Tests")
    class EnumValuesTests {

        @Test
        @DisplayName("Should have exactly 6 enum values")
        void shouldHaveExactlySixEnumValues() {
            ApplicationRole[] values = ApplicationRole.values();
            assertThat(values).hasSize(6);
        }

        @Test
        @DisplayName("Should contain all expected roles")
        void shouldContainAllExpectedRoles() {
            ApplicationRole[] values = ApplicationRole.values();
            assertThat(values)
                .containsExactlyInAnyOrder(
                    ApplicationRole.AGENT_USER_IDP,
                    ApplicationRole.AGENT_IDP,
                    ApplicationRole.AS_USER_IDP,
                    ApplicationRole.AUTHORIZATION_SERVER,
                    ApplicationRole.RESOURCE_SERVER,
                    ApplicationRole.AGENT
                );
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should support round-trip conversion: code -> role -> code")
        void shouldSupportRoundTripConversion() {
            for (ApplicationRole role : ApplicationRole.values()) {
                String code = role.getCode();
                ApplicationRole convertedRole = ApplicationRole.fromCode(code);
                assertThat(convertedRole).isEqualTo(role);
            }
        }

        @Test
        @DisplayName("Should have unique codes for all roles")
        void shouldHaveUniqueCodesForAllRoles() {
            long distinctCodeCount = Arrays.stream(ApplicationRole.values())
                .map(ApplicationRole::getCode)
                .distinct()
                .count();
            
            assertThat(distinctCodeCount)
                .isEqualTo(ApplicationRole.values().length);
        }

        @Test
        @DisplayName("Should have unique descriptions for all roles")
        void shouldHaveUniqueDescriptionsForAllRoles() {
            long distinctDescriptionCount = Arrays.stream(ApplicationRole.values())
                .map(ApplicationRole::getDescription)
                .distinct()
                .count();
            
            assertThat(distinctDescriptionCount)
                .isEqualTo(ApplicationRole.values().length);
        }
    }
}
