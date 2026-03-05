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
 * Unit tests for {@link BindingInstanceAdminController}.
 * <p>
 * Tests the binding instances admin controller.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("BindingInstanceAdminController Tests")
class BindingInstanceAdminControllerTest {

    private BindingInstanceAdminController controller;

    @BeforeEach
    void setUp() {
        controller = new BindingInstanceAdminController();
    }

    @Nested
    @DisplayName("bindingsPage() Tests")
    class BindingsPageTests {

        @Test
        @DisplayName("Should return bindings page view")
        void shouldReturnBindingsPageView() {
            // Act
            String viewName = controller.bindingsPage();

            // Assert
            assertThat(viewName).isEqualTo("admin/bindings");
        }

        @Test
        @DisplayName("Should handle multiple calls to bindingsPage")
        void shouldHandleMultipleCallsToBindingsPage() {
            // Act
            String viewName1 = controller.bindingsPage();
            String viewName2 = controller.bindingsPage();

            // Assert
            assertThat(viewName1).isEqualTo("admin/bindings");
            assertThat(viewName2).isEqualTo("admin/bindings");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create controller successfully")
        void shouldCreateControllerSuccessfully() {
            // Act
            BindingInstanceAdminController controller = new BindingInstanceAdminController();

            // Assert
            assertThat(controller).isNotNull();
        }
    }
}
