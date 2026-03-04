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
package com.alibaba.openagentauth.core.audit.factory;

import com.alibaba.openagentauth.core.audit.builder.AuditEventBuilder;
import com.alibaba.openagentauth.core.audit.builder.AuditFilterBuilder;
import com.alibaba.openagentauth.core.audit.impl.DefaultAuditService;
import com.alibaba.openagentauth.core.audit.impl.InMemoryAuditStorage;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuditFactory Tests")
class AuditFactoryTest {

    @Nested
    @DisplayName("CreateEvent Tests")
    class CreateEventTests {

        @Test
        @DisplayName("Should create a basic audit event builder")
        void shouldCreateBasicAuditEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createEvent();

            // Assert
            assertThat(builder).isNotNull();
        }
    }

    @Nested
    @DisplayName("Predefined Event Factory Methods Tests")
    class PredefinedEventFactoryMethodsTests {

        @Test
        @DisplayName("Should create authorization granted event builder")
        void shouldCreateAuthorizationGrantedEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createAuthorizationGrantedEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create authorization denied event builder")
        void shouldCreateAuthorizationDeniedEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createAuthorizationDeniedEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create policy evaluation success event builder")
        void shouldCreatePolicyEvaluationSuccessEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createPolicyEvaluationSuccessEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create policy evaluation failure event builder")
        void shouldCreatePolicyEvaluationFailureEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createPolicyEvaluationFailureEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create resource access granted event builder")
        void shouldCreateResourceAccessGrantedEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createResourceAccessGrantedEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create resource access denied event builder")
        void shouldCreateResourceAccessDeniedEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createResourceAccessDeniedEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create security violation event builder")
        void shouldCreateSecurityViolationEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createSecurityViolationEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create authentication failure event builder")
        void shouldCreateAuthenticationFailureEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createAuthenticationFailureEvent();

            // Assert
            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create suspicious activity event builder")
        void shouldCreateSuspiciousActivityEventBuilder() {
            // Act
            AuditEventBuilder builder = AuditFactory.createSuspiciousActivityEvent();

            // Assert
            assertThat(builder).isNotNull();
        }
    }

    @Nested
    @DisplayName("CreateFilter Tests")
    class CreateFilterTests {

        @Test
        @DisplayName("Should create audit filter builder")
        void shouldCreateAuditFilterBuilder() {
            // Act
            AuditFilterBuilder builder = AuditFactory.createFilter();

            // Assert
            assertThat(builder).isNotNull();
        }
    }

    @Nested
    @DisplayName("CreateAuditService Tests")
    class CreateAuditServiceTests {

        @Test
        @DisplayName("Should create in-memory audit service")
        void shouldCreateInMemoryAuditService() {
            // Act
            DefaultAuditService service = AuditFactory.createInMemoryAuditService();

            // Assert
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should create audit service with custom storage")
        void shouldCreateAuditServiceWithCustomStorage() {
            // Arrange
            InMemoryAuditStorage storage = new InMemoryAuditStorage();

            // Act
            DefaultAuditService service = AuditFactory.createAuditService(storage);

            // Assert
            assertThat(service).isNotNull();
        }
    }
}
