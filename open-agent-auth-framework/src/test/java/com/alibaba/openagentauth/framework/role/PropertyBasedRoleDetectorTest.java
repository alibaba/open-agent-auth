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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link PropertyBasedRoleDetector}.
 * <p>
 * This test class validates role detection functionality including:
 * </p>
 * <ul>
 *   <li>Role detection from various configuration sources</li>
 *   <li>Priority order of configuration keys</li>
 *   <li>Error handling for missing or invalid configurations</li>
 *   <li>Thread safety and caching behavior</li>
 *   <li>Environment variable support</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("PropertyBasedRoleDetector Tests")
class PropertyBasedRoleDetectorTest {

    private static final String PRIMARY_CONFIG_KEY = "open-agent-auth.role";
    private static final String ALTERNATIVE_CONFIG_KEY = "open-agent-auth.agent-auth.role";

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create detector with valid properties map")
        void shouldCreateDetectorWithValidProperties() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");

            // Act
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Assert
            assertThat(detector).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when properties is null")
        void shouldThrowExceptionWhenPropertiesIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new PropertyBasedRoleDetector(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Properties");
        }

        @Test
        @DisplayName("Should create detector with default constructor")
        void shouldCreateDetectorWithDefaultConstructor() {
            // Act
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector();

            // Assert
            assertThat(detector).isNotNull();
        }
    }

    @Nested
    @DisplayName("detectRole() - Primary Configuration Key")
    class PrimaryConfigKeyTests {

        @Test
        @DisplayName("Should detect agent-user-idp from primary config key")
        void shouldDetectAgentUserIdpFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT_USER_IDP);
        }

        @Test
        @DisplayName("Should detect agent-idp from primary config key")
        void shouldDetectAgentIdpFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT_IDP);
        }

        @Test
        @DisplayName("Should detect as-user-idp from primary config key")
        void shouldDetectAsUserIdpFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "as-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AS_USER_IDP);
        }

        @Test
        @DisplayName("Should detect authorization-server from primary config key")
        void shouldDetectAuthorizationServerFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should detect resource-server from primary config key")
        void shouldDetectResourceServerFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "resource-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.RESOURCE_SERVER);
        }

        @Test
        @DisplayName("Should detect agent from primary config key")
        void shouldDetectAgentFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT);
        }

        @Test
        @DisplayName("Should handle uppercase role code from primary config key")
        void shouldHandleUppercaseRoleCodeFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "AUTHORIZATION-SERVER");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should handle mixed case role code from primary config key")
        void shouldHandleMixedCaseRoleCodeFromPrimaryConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "Authorization-Server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should handle role code with leading/trailing whitespace")
        void shouldHandleRoleCodeWithWhitespace() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "  authorization-server  ");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }
    }

    @Nested
    @DisplayName("detectRole() - Alternative Configuration Key")
    class AlternativeConfigKeyTests {

        @Test
        @DisplayName("Should detect role from alternative config key when primary is missing")
        void shouldDetectRoleFromAlternativeConfigKeyWhenPrimaryIsMissing() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(ALTERNATIVE_CONFIG_KEY, "resource-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.RESOURCE_SERVER);
        }

        @Test
        @DisplayName("Should prefer primary config key over alternative")
        void shouldPreferPrimaryConfigKeyOverAlternative() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            properties.put(ALTERNATIVE_CONFIG_KEY, "resource-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should handle uppercase role code from alternative config key")
        void shouldHandleUppercaseRoleCodeFromAlternativeConfigKey() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(ALTERNATIVE_CONFIG_KEY, "AGENT");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT);
        }
    }

    @Nested
    @DisplayName("detectRole() - Environment Variables")
    class EnvironmentVariableTests {

        @Test
        @DisplayName("Should detect role from environment variable")
        void shouldDetectRoleFromEnvironmentVariable() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put("OPEN_AGENT_AUTH_ROLE_CUSTOM", "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT_IDP);
        }

        @Test
        @DisplayName("Should prefer primary config key over environment variable")
        void shouldPreferPrimaryConfigKeyOverEnvironmentVariable() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            properties.put("OPEN_AGENT_AUTH_ROLE_CUSTOM", "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should prefer alternative config key over environment variable")
        void shouldPreferAlternativeConfigKeyOverEnvironmentVariable() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(ALTERNATIVE_CONFIG_KEY, "resource-server");
            properties.put("OPEN_AGENT_AUTH_ROLE_CUSTOM", "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.RESOURCE_SERVER);
        }

        @Test
        @DisplayName("Should handle environment variable with different suffix")
        void shouldHandleEnvironmentVariableWithDifferentSuffix() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put("OPEN_AGENT_AUTH_ROLE_PRODUCTION", "agent-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT_USER_IDP);
        }
    }

    @Nested
    @DisplayName("detectRole() - Error Handling")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when role is not configured")
        void shouldThrowExceptionWhenRoleIsNotConfigured() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Application role is not configured")
                .hasMessageContaining("open-agent-auth.role");
        }

        @Test
        @DisplayName("Should throw exception when role code is empty string")
        void shouldThrowExceptionWhenRoleCodeIsEmptyString() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Application role is not configured");
        }

        @Test
        @DisplayName("Should throw exception when role code is whitespace only")
        void shouldThrowExceptionWhenRoleCodeIsWhitespaceOnly() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "   ");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Application role is not configured");
        }

        @Test
        @DisplayName("Should throw exception when role code is invalid")
        void shouldThrowExceptionWhenRoleCodeIsInvalid() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "invalid-role");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Invalid application role")
                .hasMessageContaining("invalid-role")
                .hasMessageContaining("agent-user-idp");
        }

        @Test
        @DisplayName("Should throw exception with all valid role codes in error message")
        void shouldThrowExceptionWithAllValidRoleCodesInErrorMessage() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "invalid-role");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("agent-user-idp")
                .hasMessageContaining("agent-idp")
                .hasMessageContaining("as-user-idp")
                .hasMessageContaining("authorization-server")
                .hasMessageContaining("resource-server")
                .hasMessageContaining("agent");
        }
    }

    @Nested
    @DisplayName("detectRole() - Caching Behavior")
    class CachingTests {

        @Test
        @DisplayName("Should cache detected role for subsequent calls")
        void shouldCacheDetectedRoleForSubsequentCalls() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role1 = detector.detectRole();
            ApplicationRole role2 = detector.detectRole();
            ApplicationRole role3 = detector.detectRole();

            // Assert
            assertThat(role1).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
            assertThat(role2).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
            assertThat(role3).isEqualTo(ApplicationRole.AUTHORIZATION_SERVER);
        }

        @Test
        @DisplayName("Should return same instance for cached role")
        void shouldReturnSameInstanceForCachedRole() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role1 = detector.detectRole();
            ApplicationRole role2 = detector.detectRole();

            // Assert
            assertThat(role1).isSameAs(role2);
        }
    }

    @Nested
    @DisplayName("detectRole() - Thread Safety")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should be thread-safe when detecting role concurrently")
        void shouldBeThreadSafeWhenDetectingRoleConcurrently() throws InterruptedException {
            // Arrange
            Map<String, String> properties = new ConcurrentHashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "resource-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            ApplicationRole[] results = new ApplicationRole[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    results[index] = detector.detectRole();
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert
            for (ApplicationRole result : results) {
                assertThat(result).isEqualTo(ApplicationRole.RESOURCE_SERVER);
            }
        }

        @Test
        @DisplayName("Should handle concurrent calls with caching correctly")
        void shouldHandleConcurrentCallsWithCachingCorrectly() throws InterruptedException {
            // Arrange
            Map<String, String> properties = new ConcurrentHashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            int threadCount = 20;
            Thread[] threads = new Thread[threadCount];
            ApplicationRole[] results = new ApplicationRole[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    results[index] = detector.detectRole();
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert
            for (int i = 0; i < threadCount; i++) {
                assertThat(results[i]).isEqualTo(ApplicationRole.AGENT_USER_IDP);
                if (i > 0) {
                    assertThat(results[i]).isSameAs(results[0]);
                }
            }
        }
    }

    @Nested
    @DisplayName("isRole() - Default Method")
    class IsRoleTests {

        @Test
        @DisplayName("Should return true when application is the specified role")
        void shouldReturnTrueWhenApplicationIsSpecifiedRole() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isAuthorizationServer = detector.isRole(ApplicationRole.AUTHORIZATION_SERVER);
            boolean isResourceServer = detector.isRole(ApplicationRole.RESOURCE_SERVER);

            // Assert
            assertThat(isAuthorizationServer).isTrue();
            assertThat(isResourceServer).isFalse();
        }

        @Test
        @DisplayName("Should return false when role does not match")
        void shouldReturnFalseWhenRoleDoesNotMatch() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isAgent = detector.isRole(ApplicationRole.AGENT);

            // Assert
            assertThat(isAgent).isFalse();
        }
    }

    @Nested
    @DisplayName("isIdp() - Default Method")
    class IsIdpTests {

        @Test
        @DisplayName("Should return true for agent-user-idp")
        void shouldReturnTrueForAgentUserIdp() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isIdp = detector.isIdp();

            // Assert
            assertThat(isIdp).isTrue();
        }

        @Test
        @DisplayName("Should return true for agent-idp")
        void shouldReturnTrueForAgentIdp() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isIdp = detector.isIdp();

            // Assert
            assertThat(isIdp).isTrue();
        }

        @Test
        @DisplayName("Should return true for as-user-idp")
        void shouldReturnTrueForAsUserIdp() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "as-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isIdp = detector.isIdp();

            // Assert
            assertThat(isIdp).isTrue();
        }

        @Test
        @DisplayName("Should return false for authorization-server")
        void shouldReturnFalseForAuthorizationServer() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isIdp = detector.isIdp();

            // Assert
            assertThat(isIdp).isFalse();
        }

        @Test
        @DisplayName("Should return false for resource-server")
        void shouldReturnFalseForResourceServer() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "resource-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isIdp = detector.isIdp();

            // Assert
            assertThat(isIdp).isFalse();
        }

        @Test
        @DisplayName("Should return false for agent")
        void shouldReturnFalseForAgent() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isIdp = detector.isIdp();

            // Assert
            assertThat(isIdp).isFalse();
        }
    }

    @Nested
    @DisplayName("isServer() - Default Method")
    class IsServerTests {

        @Test
        @DisplayName("Should return true for authorization-server")
        void shouldReturnTrueForAuthorizationServer() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "authorization-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isServer = detector.isServer();

            // Assert
            assertThat(isServer).isTrue();
        }

        @Test
        @DisplayName("Should return true for resource-server")
        void shouldReturnTrueForResourceServer() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "resource-server");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isServer = detector.isServer();

            // Assert
            assertThat(isServer).isTrue();
        }

        @Test
        @DisplayName("Should return false for agent-user-idp")
        void shouldReturnFalseForAgentUserIdp() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isServer = detector.isServer();

            // Assert
            assertThat(isServer).isFalse();
        }

        @Test
        @DisplayName("Should return false for agent-idp")
        void shouldReturnFalseForAgentIdp() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isServer = detector.isServer();

            // Assert
            assertThat(isServer).isFalse();
        }

        @Test
        @DisplayName("Should return false for agent")
        void shouldReturnFalseForAgent() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            boolean isServer = detector.isServer();

            // Assert
            assertThat(isServer).isFalse();
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle empty properties map")
        void shouldHandleEmptyPropertiesMap() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Application role is not configured");
        }

        @Test
        @DisplayName("Should handle properties map with null values")
        void shouldHandlePropertiesMapWithNullValues() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, null);
            properties.put(ALTERNATIVE_CONFIG_KEY, null);
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act & Assert
            assertThatThrownBy(() -> detector.detectRole())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Application role is not configured");
        }

        @Test
        @DisplayName("Should handle concurrent map as properties")
        void shouldHandleConcurrentMapAsProperties() {
            // Arrange
            Map<String, String> properties = new ConcurrentHashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "agent");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AGENT);
        }

        @Test
        @DisplayName("Should handle role code with hyphens and underscores")
        void shouldHandleRoleCodeWithHyphensAndUnderscores() {
            // Arrange
            Map<String, String> properties = new HashMap<>();
            properties.put(PRIMARY_CONFIG_KEY, "as-user-idp");
            PropertyBasedRoleDetector detector = new PropertyBasedRoleDetector(properties);

            // Act
            ApplicationRole role = detector.detectRole();

            // Assert
            assertThat(role).isEqualTo(ApplicationRole.AS_USER_IDP);
        }
    }
}
