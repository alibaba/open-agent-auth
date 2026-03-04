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
 * Unit tests for {@link AuditAdminController}.
 * <p>
 * Tests the audit events admin controller.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditAdminController Tests")
class AuditAdminControllerTest {

    private AuditAdminController controller;

    @BeforeEach
    void setUp() {
        controller = new AuditAdminController();
    }

    @Nested
    @DisplayName("auditPage() Tests")
    class AuditPageTests {

        @Test
        @DisplayName("Should return audit page view")
        void shouldReturnAuditPageView() {
            // Act
            String viewName = controller.auditPage();

            // Assert
            assertThat(viewName).isEqualTo("admin/audit");
        }

        @Test
        @DisplayName("Should handle multiple calls to auditPage")
        void shouldHandleMultipleCallsToAuditPage() {
            // Act
            String viewName1 = controller.auditPage();
            String viewName2 = controller.auditPage();

            // Assert
            assertThat(viewName1).isEqualTo("admin/audit");
            assertThat(viewName2).isEqualTo("admin/audit");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create controller successfully")
        void shouldCreateControllerSuccessfully() {
            // Act
            AuditAdminController controller = new AuditAdminController();

            // Assert
            assertThat(controller).isNotNull();
        }
    }
}
