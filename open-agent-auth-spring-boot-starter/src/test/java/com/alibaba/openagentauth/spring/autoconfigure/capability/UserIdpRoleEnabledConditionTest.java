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
package com.alibaba.openagentauth.spring.autoconfigure.capability;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserIdpRoleEnabledCondition}.
 * <p>
 * This test class verifies the custom Spring Boot condition that checks whether
 * at least one User IDP role (agent-user-idp or as-user-idp) is enabled.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("UserIdpRoleEnabledCondition Tests")
class UserIdpRoleEnabledConditionTest {

    private static final String AGENT_USER_IDP_ENABLED = "open-agent-auth.roles.agent-user-idp.enabled";
    private static final String AS_USER_IDP_ENABLED = "open-agent-auth.roles.as-user-idp.enabled";

    private final UserIdpRoleEnabledCondition condition = new UserIdpRoleEnabledCondition();
    private final ConditionContext context = mock(ConditionContext.class);
    private final Environment environment = mock(Environment.class);
    private final AnnotatedTypeMetadata metadata = mock(AnnotatedTypeMetadata.class);

    @Nested
    @DisplayName("Match Scenarios")
    class MatchScenarios {

        @Test
        @DisplayName("Should match when only agent-user-idp is enabled")
        void shouldMatchWhenOnlyAgentUserIdpEnabled() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn("true");
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn(null);

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isTrue();
            assertThat(outcome.getMessage()).contains("At least one User IDP role is enabled");
        }

        @Test
        @DisplayName("Should match when only as-user-idp is enabled")
        void shouldMatchWhenOnlyAsUserIdpEnabled() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn(null);
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("true");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isTrue();
            assertThat(outcome.getMessage()).contains("At least one User IDP role is enabled");
        }

        @Test
        @DisplayName("Should match when both User IDP roles are enabled")
        void shouldMatchWhenBothUserIdpRolesEnabled() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn("true");
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("true");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isTrue();
            assertThat(outcome.getMessage()).contains("At least one User IDP role is enabled");
        }

        @Test
        @DisplayName("Should match with case-insensitive 'TRUE'")
        void shouldMatchWithCaseInsensitiveTrue() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn("TRUE");
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn(null);

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isTrue();
        }

        @Test
        @DisplayName("Should match with mixed case 'True'")
        void shouldMatchWithMixedCaseTrue() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn(null);
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("True");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isTrue();
        }
    }

    @Nested
    @DisplayName("No Match Scenarios")
    class NoMatchScenarios {

        @Test
        @DisplayName("Should not match when no User IDP role is enabled")
        void shouldNotMatchWhenNoUserIdpRoleEnabled() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn(null);
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn(null);

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isFalse();
            assertThat(outcome.getMessage()).contains("No User IDP role is enabled");
        }

        @Test
        @DisplayName("Should not match when both User IDP roles are explicitly disabled")
        void shouldNotMatchWhenBothExplicitlyDisabled() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn("false");
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("false");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isFalse();
            assertThat(outcome.getMessage()).contains("No User IDP role is enabled");
        }

        @Test
        @DisplayName("Should not match when properties have invalid values")
        void shouldNotMatchWhenPropertiesHaveInvalidValues() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn("yes");
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("1");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isFalse();
        }

        @Test
        @DisplayName("Should not match when properties are empty strings")
        void shouldNotMatchWhenPropertiesAreEmptyStrings() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn("");
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isFalse();
        }
    }

    @Nested
    @DisplayName("Authorization Server Isolation Scenarios")
    class AuthorizationServerIsolationScenarios {

        @Test
        @DisplayName("Should not match for Authorization Server only scenario")
        void shouldNotMatchForAuthorizationServerOnly() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn(null);
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn(null);

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isFalse();
        }

        @Test
        @DisplayName("Should match for AS User IDP co-existing with Authorization Server")
        void shouldMatchForAsUserIdpCoexistingWithAuthorizationServer() {
            when(context.getEnvironment()).thenReturn(environment);
            when(environment.getProperty(AGENT_USER_IDP_ENABLED)).thenReturn(null);
            when(environment.getProperty(AS_USER_IDP_ENABLED)).thenReturn("true");

            ConditionOutcome outcome = condition.getMatchOutcome(context, metadata);

            assertThat(outcome.isMatch()).isTrue();
        }
    }
}
