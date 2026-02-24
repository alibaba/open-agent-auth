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
package com.alibaba.openagentauth.spring.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ConfigurationValidator}.
 * <p>
 * This test class verifies the auto-configuration behavior of ConfigurationValidator,
 * including conditional loading, configuration validation, and role co-existence detection.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ConfigurationValidator Tests")
class ConfigurationValidatorTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            ConfigurationValidator.class
        ));

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when open-agent-auth.enabled=true")
        void shouldLoadWhenEnabled() {
            contextRunner
                .withPropertyValues("open-agent-auth.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(ConfigurationValidator.class);
                });
        }

        @Test
        @DisplayName("Should not load when open-agent-auth.enabled=false")
        void shouldNotLoadWhenDisabled() {
            contextRunner
                .withPropertyValues("open-agent-auth.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(ConfigurationValidator.class);
                });
        }

        @Test
        @DisplayName("Should not load when open-agent-auth.enabled is not set")
        void shouldNotLoadWhenEnabledNotSet() {
            contextRunner
                .run(context -> {
                    assertThat(context).doesNotHaveBean(ConfigurationValidator.class);
                });
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should pass validation when no roles configured")
        void shouldPassValidationWhenNoRolesConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ConfigurationValidator.class);
                    assertThat(context).hasNotFailed();
                });
        }

        @Test
        @DisplayName("Should pass validation when role has required capabilities")
        void shouldPassValidationWhenRoleHasRequiredCapabilities() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.capabilities.user-authentication.enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ConfigurationValidator.class);
                    assertThat(context).hasNotFailed();
                });
        }

        @Test
        @DisplayName("Should start successfully even when capability missing")
        void shouldStartSuccessfullyEvenWhenCapabilityMissing() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=false",
                    "open-agent-auth.capabilities.user-authentication.enabled=false"
                )
                .run(context -> {
                    // ConfigurationValidator only logs warnings, does not throw exceptions
                    assertThat(context).hasSingleBean(ConfigurationValidator.class);
                    assertThat(context).hasNotFailed();
                });
        }
    }

    @Nested
    @DisplayName("Role Coexistence Tests")
    class RoleCoexistenceTests {

        @Test
        @DisplayName("Should detect Agent User IDP and AS User IDP coexistence")
        void shouldDetectAgentUserIdpAndAsUserIdpCoexistence() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ConfigurationValidator.class);
                    assertThat(context).hasNotFailed();
                });
        }

        @Test
        @DisplayName("Should detect Authorization Server and AS User IDP coexistence")
        void shouldDetectAuthorizationServerAndAsUserIdpCoexistence() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.authorization-server.enabled=true",
                    "open-agent-auth.roles.as-user-idp.enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ConfigurationValidator.class);
                    assertThat(context).hasNotFailed();
                });
        }
    }
}
