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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AdminProperties}.
 * <p>
 * Tests the configuration properties for the Admin Console.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AdminProperties Tests")
class AdminPropertiesTest {

    @Nested
    @DisplayName("Default Values Tests")
    class DefaultValuesTests {

        @Test
        @DisplayName("Should have default enabled value as false")
        void shouldHaveDefaultEnabledValueAsFalse() {
            // Arrange
            AdminProperties properties = new AdminProperties();

            // Act & Assert
            assertThat(properties.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("Should have default access control enabled as true")
        void shouldHaveDefaultAccessControlEnabledAsTrue() {
            // Arrange
            AdminProperties properties = new AdminProperties();

            // Act & Assert
            assertThat(properties.getAccessControl().isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should have default endpoint paths")
        void shouldHaveDefaultEndpointPaths() {
            // Arrange
            AdminProperties properties = new AdminProperties();

            // Act & Assert
            assertThat(properties.getEndpoints().getDashboard()).isEqualTo("/admin");
            assertThat(properties.getEndpoints().getWorkloads()).isEqualTo("/admin/workloads");
            assertThat(properties.getEndpoints().getBindings()).isEqualTo("/admin/bindings");
            assertThat(properties.getEndpoints().getPolicies()).isEqualTo("/admin/policies");
            assertThat(properties.getEndpoints().getAudit()).isEqualTo("/admin/audit");
        }
    }

    @Nested
    @DisplayName("Setter/Getter Tests")
    class SetterGetterTests {

        @Test
        @DisplayName("Should set and get enabled correctly")
        void shouldSetAndGetEnabledCorrectly() {
            // Arrange
            AdminProperties properties = new AdminProperties();

            // Act
            properties.setEnabled(true);

            // Assert
            assertThat(properties.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should set and get access control correctly")
        void shouldSetAndGetAccessControlCorrectly() {
            // Arrange
            AdminProperties properties = new AdminProperties();
            AdminProperties.AccessControlProperties accessControl = new AdminProperties.AccessControlProperties();
            accessControl.setEnabled(false);

            // Act
            properties.setAccessControl(accessControl);

            // Assert
            assertThat(properties.getAccessControl()).isSameAs(accessControl);
            assertThat(properties.getAccessControl().isEnabled()).isFalse();
        }

        @Test
        @DisplayName("Should set and get endpoints correctly")
        void shouldSetAndGetEndpointsCorrectly() {
            // Arrange
            AdminProperties properties = new AdminProperties();
            AdminProperties.EndpointProperties endpoints = new AdminProperties.EndpointProperties();
            endpoints.setDashboard("/custom-admin");

            // Act
            properties.setEndpoints(endpoints);

            // Assert
            assertThat(properties.getEndpoints()).isSameAs(endpoints);
            assertThat(properties.getEndpoints().getDashboard()).isEqualTo("/custom-admin");
        }
    }

    @Nested
    @DisplayName("AccessControlProperties Tests")
    class AccessControlPropertiesTests {

        @Test
        @DisplayName("Should have default enabled as true")
        void shouldHaveDefaultEnabledAsTrue() {
            // Arrange
            AdminProperties.AccessControlProperties properties = new AdminProperties.AccessControlProperties();

            // Act & Assert
            assertThat(properties.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should have default allowed subjects as empty list")
        void shouldHaveDefaultAllowedSubjectsAsEmptyList() {
            // Arrange
            AdminProperties.AccessControlProperties properties = new AdminProperties.AccessControlProperties();

            // Act & Assert
            assertThat(properties.getAllowedSessionSubjects()).isNotNull().isEmpty();
        }

        @Test
        @DisplayName("Should set and get enabled correctly")
        void shouldSetAndGetEnabledCorrectly() {
            // Arrange
            AdminProperties.AccessControlProperties properties = new AdminProperties.AccessControlProperties();

            // Act
            properties.setEnabled(false);

            // Assert
            assertThat(properties.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("Should set and get allowed subjects correctly")
        void shouldSetAndGetAllowedSubjectsCorrectly() {
            // Arrange
            AdminProperties.AccessControlProperties properties = new AdminProperties.AccessControlProperties();
            List<String> subjects = List.of("admin", "operator");

            // Act
            properties.setAllowedSessionSubjects(subjects);

            // Assert
            assertThat(properties.getAllowedSessionSubjects()).isEqualTo(subjects);
        }

        @Test
        @DisplayName("Should allow null allowed subjects")
        void shouldAllowNullAllowedSubjects() {
            // Arrange
            AdminProperties.AccessControlProperties properties = new AdminProperties.AccessControlProperties();

            // Act
            properties.setAllowedSessionSubjects(null);

            // Assert
            assertThat(properties.getAllowedSessionSubjects()).isNull();
        }
    }

    @Nested
    @DisplayName("EndpointProperties Tests")
    class EndpointPropertiesTests {

        @Test
        @DisplayName("Should have default dashboard path")
        void shouldHaveDefaultDashboardPath() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act & Assert
            assertThat(properties.getDashboard()).isEqualTo("/admin");
        }

        @Test
        @DisplayName("Should have default workloads path")
        void shouldHaveDefaultWorkloadsPath() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act & Assert
            assertThat(properties.getWorkloads()).isEqualTo("/admin/workloads");
        }

        @Test
        @DisplayName("Should have default bindings path")
        void shouldHaveDefaultBindingsPath() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act & Assert
            assertThat(properties.getBindings()).isEqualTo("/admin/bindings");
        }

        @Test
        @DisplayName("Should have default policies path")
        void shouldHaveDefaultPoliciesPath() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act & Assert
            assertThat(properties.getPolicies()).isEqualTo("/admin/policies");
        }

        @Test
        @DisplayName("Should have default audit path")
        void shouldHaveDefaultAuditPath() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act & Assert
            assertThat(properties.getAudit()).isEqualTo("/admin/audit");
        }

        @Test
        @DisplayName("Should set and get dashboard correctly")
        void shouldSetAndGetDashboardCorrectly() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act
            properties.setDashboard("/custom-dashboard");

            // Assert
            assertThat(properties.getDashboard()).isEqualTo("/custom-dashboard");
        }

        @Test
        @DisplayName("Should set and get workloads correctly")
        void shouldSetAndGetWorkloadsCorrectly() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act
            properties.setWorkloads("/custom-workloads");

            // Assert
            assertThat(properties.getWorkloads()).isEqualTo("/custom-workloads");
        }

        @Test
        @DisplayName("Should set and get bindings correctly")
        void shouldSetAndGetBindingsCorrectly() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act
            properties.setBindings("/custom-bindings");

            // Assert
            assertThat(properties.getBindings()).isEqualTo("/custom-bindings");
        }

        @Test
        @DisplayName("Should set and get policies correctly")
        void shouldSetAndGetPoliciesCorrectly() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act
            properties.setPolicies("/custom-policies");

            // Assert
            assertThat(properties.getPolicies()).isEqualTo("/custom-policies");
        }

        @Test
        @DisplayName("Should set and get audit correctly")
        void shouldSetAndGetAuditCorrectly() {
            // Arrange
            AdminProperties.EndpointProperties properties = new AdminProperties.EndpointProperties();

            // Act
            properties.setAudit("/custom-audit");

            // Assert
            assertThat(properties.getAudit()).isEqualTo("/custom-audit");
        }
    }
}
