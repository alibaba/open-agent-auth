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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PolicyRegistryAdminController}.
 * <p>
 * Tests the policy registry admin controller.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("PolicyRegistryAdminController Tests")
class PolicyRegistryAdminControllerTest {

    private PolicyRegistryAdminController controller;

    @BeforeEach
    void setUp() {
        controller = new PolicyRegistryAdminController();
    }

    @Nested
    @DisplayName("policiesPage() Tests")
    class PoliciesPageTests {

        @Test
        @DisplayName("Should return policies page view")
        void shouldReturnPoliciesPageView() {
            // Act
            String viewName = controller.policiesPage();

            // Assert
            assertThat(viewName).isEqualTo("admin/policies");
        }

        @Test
        @DisplayName("Should handle multiple calls to policiesPage")
        void shouldHandleMultipleCallsToPoliciesPage() {
            // Act
            String viewName1 = controller.policiesPage();
            String viewName2 = controller.policiesPage();

            // Assert
            assertThat(viewName1).isEqualTo("admin/policies");
            assertThat(viewName2).isEqualTo("admin/policies");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create controller successfully")
        void shouldCreateControllerSuccessfully() {
            // Act
            PolicyRegistryAdminController controller = new PolicyRegistryAdminController();

            // Assert
            assertThat(controller).isNotNull();
        }
    }
}
