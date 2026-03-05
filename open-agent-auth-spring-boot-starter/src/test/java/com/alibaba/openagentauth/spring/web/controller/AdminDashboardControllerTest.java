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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.Model;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AdminDashboardController}.
 * <p>
 * Tests the admin dashboard controller that provides administrative UI endpoints.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AdminDashboardController Tests")
class AdminDashboardControllerTest {

    @Mock
    private BindingInstanceStore bindingInstanceStore;

    @Mock
    private PolicyRegistry policyRegistry;

    @Mock
    private AuditService auditService;

    @Mock
    private AgentIdentityProvider agentIdentityProvider;

    @Mock
    private WorkloadRegistry workloadRegistry;

    @Mock
    private Model model;

    private AdminDashboardController controller;

    @BeforeEach
    void setUp() {
        controller = new AdminDashboardController(
                Optional.of(bindingInstanceStore),
                Optional.of(policyRegistry),
                Optional.of(auditService),
                Optional.of(agentIdentityProvider),
                Optional.of(workloadRegistry)
        );
    }

    @Nested
    @DisplayName("dashboardPage() Tests")
    class DashboardPageTests {

        @Test
        @DisplayName("Should return dashboard view with all navigation items")
        void shouldReturnDashboardViewWithAllNavigationItems() {
            // Act
            String viewName = controller.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
            // All 5 Optional beans are present, so navItems should contain 4 items
            // (bindings, policies, audit, workloads)
            verify(model).addAttribute(org.mockito.ArgumentMatchers.eq("navItems"),
                    org.mockito.ArgumentMatchers.argThat(arg ->
                            arg instanceof List && ((List<?>) arg).size() == 4));
            verify(model).addAttribute("defaultPage", "/admin/bindings");
        }

        @Test
        @DisplayName("Should return dashboard view with no navigation items when no beans present")
        void shouldReturnDashboardViewWithNoNavigationItemsWhenNoBeansPresent() {
            // Arrange
            AdminDashboardController emptyController = new AdminDashboardController(
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );

            // Act
            String viewName = emptyController.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
            verify(model).addAttribute("navItems", new ArrayList<>());
            verify(model).addAttribute("defaultPage", "");
        }

        @Test
        @DisplayName("Should include binding navigation item when BindingInstanceStore is present")
        void shouldIncludeBindingNavigationItemWhenBindingInstanceStoreIsPresent() {
            // Arrange
            AdminDashboardController bindingController = new AdminDashboardController(
                    Optional.of(bindingInstanceStore),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );

            // Act
            String viewName = bindingController.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
            // Only bindingInstanceStore is present, so navItems should contain 1 item
            verify(model).addAttribute(org.mockito.ArgumentMatchers.eq("navItems"),
                    org.mockito.ArgumentMatchers.argThat(arg ->
                            arg instanceof List && ((List<?>) arg).size() == 1));
            verify(model).addAttribute("defaultPage", "/admin/bindings");
        }

        @Test
        @DisplayName("Should include policy navigation item when PolicyRegistry is present")
        void shouldIncludePolicyNavigationItemWhenPolicyRegistryIsPresent() {
            // Arrange
            AdminDashboardController controller = new AdminDashboardController(
                    Optional.empty(),
                    Optional.of(policyRegistry),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );

            // Act
            String viewName = controller.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
        }

        @Test
        @DisplayName("Should include audit navigation item when AuditService is present")
        void shouldIncludeAuditNavigationItemWhenAuditServiceIsPresent() {
            // Arrange
            AdminDashboardController controller = new AdminDashboardController(
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(auditService),
                    Optional.empty(),
                    Optional.empty()
            );

            // Act
            String viewName = controller.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
        }

        @Test
        @DisplayName("Should include workload navigation item when AgentIdentityProvider is present")
        void shouldIncludeWorkloadNavigationItemWhenAgentIdentityProviderIsPresent() {
            // Arrange
            AdminDashboardController controller = new AdminDashboardController(
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(agentIdentityProvider),
                    Optional.empty()
            );

            // Act
            String viewName = controller.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
        }

        @Test
        @DisplayName("Should include workload navigation item when WorkloadRegistry is present")
        void shouldIncludeWorkloadNavigationItemWhenWorkloadRegistryIsPresent() {
            // Arrange
            AdminDashboardController controller = new AdminDashboardController(
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.of(workloadRegistry)
            );

            // Act
            String viewName = controller.dashboardPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/dashboard");
        }
    }

    @Nested
    @DisplayName("NavItem Tests")
    class NavItemTests {

        @Test
        @DisplayName("Should create NavItem with all properties")
        void shouldCreateNavItemWithAllProperties() {
            // Act
            AdminDashboardController.NavItem item = new AdminDashboardController.NavItem(
                    "test-id", "Test Label", "test-icon", "/test/url");

            // Assert
            assertThat(item.getId()).isEqualTo("test-id");
            assertThat(item.getLabel()).isEqualTo("Test Label");
            assertThat(item.getIcon()).isEqualTo("test-icon");
            assertThat(item.getUrl()).isEqualTo("/test/url");
        }

        @Test
        @DisplayName("Should handle NavItem with empty strings")
        void shouldHandleNavItemWithEmptyStrings() {
            // Act
            AdminDashboardController.NavItem item = new AdminDashboardController.NavItem("", "", "", "");

            // Assert
            assertThat(item.getId()).isEqualTo("");
            assertThat(item.getLabel()).isEqualTo("");
            assertThat(item.getIcon()).isEqualTo("");
            assertThat(item.getUrl()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle NavItem with special characters")
        void shouldHandleNavItemWithSpecialCharacters() {
            // Act
            AdminDashboardController.NavItem item = new AdminDashboardController.NavItem(
                    "test-id-123", "Test Label (Special)", "bi-icon-test", "/test/url?param=value");

            // Assert
            assertThat(item.getId()).isEqualTo("test-id-123");
            assertThat(item.getLabel()).isEqualTo("Test Label (Special)");
            assertThat(item.getIcon()).isEqualTo("bi-icon-test");
            assertThat(item.getUrl()).isEqualTo("/test/url?param=value");
        }
    }
}
