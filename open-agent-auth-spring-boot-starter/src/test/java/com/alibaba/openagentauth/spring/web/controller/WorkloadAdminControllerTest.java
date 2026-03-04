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

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link WorkloadAdminController}.
 * <p>
 * Tests the workload identity admin controller.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("WorkloadAdminController Tests")
class WorkloadAdminControllerTest {

    @Mock
    private WorkloadRegistry workloadRegistry;

    @Mock
    private AgentIdentityProvider agentIdentityProvider;

    @Mock
    private Model model;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create controller in read-write mode when AgentIdentityProvider is present")
        void shouldCreateControllerInReadWriteModeWhenAgentIdentityProviderIsPresent() {
            // Act
            WorkloadAdminController controller = new WorkloadAdminController(Optional.of(agentIdentityProvider));

            // Assert
            assertThat(controller).isNotNull();
        }

        @Test
        @DisplayName("Should create controller in read-only mode when AgentIdentityProvider is absent")
        void shouldCreateControllerInReadOnlyModeWhenAgentIdentityProviderIsAbsent() {
            // Act
            WorkloadAdminController controller = new WorkloadAdminController(Optional.empty());

            // Assert
            assertThat(controller).isNotNull();
        }
    }

    @Nested
    @DisplayName("workloadsPage() Tests - Read-Write Mode")
    class WorkloadsPageReadWriteModeTests {

        private WorkloadAdminController controller;

        @BeforeEach
        void setUp() {
            controller = new WorkloadAdminController(Optional.of(agentIdentityProvider));
        }

        @Test
        @DisplayName("Should return workloads page view with readOnly=false")
        void shouldReturnWorkloadsPageViewWithReadOnlyFalse() {
            // Act
            String viewName = controller.workloadsPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/workloads");
            verify(model).addAttribute("readOnly", false);
        }

        @Test
        @DisplayName("Should handle multiple calls to workloadsPage")
        void shouldHandleMultipleCallsToWorkloadsPage() {
            // Act
            String viewName1 = controller.workloadsPage(model);
            String viewName2 = controller.workloadsPage(model);

            // Assert
            assertThat(viewName1).isEqualTo("admin/workloads");
            assertThat(viewName2).isEqualTo("admin/workloads");
        }
    }

    @Nested
    @DisplayName("workloadsPage() Tests - Read-Only Mode")
    class WorkloadsPageReadOnlyModeTests {

        private WorkloadAdminController controller;

        @BeforeEach
        void setUp() {
            controller = new WorkloadAdminController(Optional.empty());
        }

        @Test
        @DisplayName("Should return workloads page view with readOnly=true")
        void shouldReturnWorkloadsPageViewWithReadOnlyTrue() {
            // Act
            String viewName = controller.workloadsPage(model);

            // Assert
            assertThat(viewName).isEqualTo("admin/workloads");
            verify(model).addAttribute("readOnly", true);
        }

        @Test
        @DisplayName("Should handle multiple calls to workloadsPage in read-only mode")
        void shouldHandleMultipleCallsToWorkloadsPageInReadOnlyMode() {
            // Act
            String viewName1 = controller.workloadsPage(model);
            String viewName2 = controller.workloadsPage(model);

            // Assert
            assertThat(viewName1).isEqualTo("admin/workloads");
            assertThat(viewName2).isEqualTo("admin/workloads");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null AgentIdentityProvider")
        void shouldHandleNullAgentIdentityProvider() {
            // Act
            WorkloadAdminController controller = new WorkloadAdminController(Optional.ofNullable(null));

            // Assert
            assertThat(controller).isNotNull();
            String viewName = controller.workloadsPage(model);
            assertThat(viewName).isEqualTo("admin/workloads");
            verify(model).addAttribute("readOnly", true);
        }
    }
}
