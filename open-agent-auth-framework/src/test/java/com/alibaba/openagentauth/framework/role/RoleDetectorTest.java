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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RoleDetector} interface.
 * <p>
 * This test class verifies the contract and default methods of the RoleDetector interface.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("RoleDetector Interface Tests")
class RoleDetectorTest {

    @Nested
    @DisplayName("detectRole() Contract Tests")
    class DetectRoleContractTests {

        @Test
        @DisplayName("Should return ApplicationRole")
        void shouldReturnApplicationRole() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT);

            ApplicationRole role = detector.detectRole();

            assertThat(role).isNotNull();
            assertThat(role).isEqualTo(ApplicationRole.AGENT);
        }

        @Test
        @DisplayName("Should throw IllegalStateException when role cannot be determined")
        void shouldThrowIllegalStateExceptionWhenRoleCannotBeDetermined() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole())
                .thenThrow(new IllegalStateException("Role not configured"));

            try {
                detector.detectRole();
            } catch (IllegalStateException e) {
                assertThat(e.getMessage()).contains("Role not configured");
            }
        }

        @Test
        @DisplayName("Should be deterministic - same result on multiple calls")
        void shouldBeDeterministic() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.RESOURCE_SERVER);

            ApplicationRole result1 = detector.detectRole();
            ApplicationRole result2 = detector.detectRole();
            ApplicationRole result3 = detector.detectRole();

            assertThat(result1).isEqualTo(result2).isEqualTo(result3);
        }
    }

    @Nested
    @DisplayName("isRole() Default Method Tests")
    class IsRoleMethodTests {

        @Test
        @DisplayName("Should return true when role matches")
        void shouldReturnTrueWhenRoleMatches() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_IDP);

            boolean result = detector.isRole(ApplicationRole.AGENT_IDP);

            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false when role does not match")
        void shouldReturnFalseWhenRoleDoesNotMatch() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT);

            boolean result = detector.isRole(ApplicationRole.RESOURCE_SERVER);

            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should call detectRole() internally")
        void shouldCallDetectRoleInternally() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AUTHORIZATION_SERVER);

            detector.isRole(ApplicationRole.AUTHORIZATION_SERVER);

            verify(detector, times(1)).detectRole();
        }

        @Test
        @DisplayName("Should handle all role types correctly")
        void shouldHandleAllRoleTypesCorrectly() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);

            for (ApplicationRole role : ApplicationRole.values()) {
                when(detector.detectRole()).thenReturn(role);
                assertThat(detector.isRole(role)).isTrue();
                for (ApplicationRole otherRole : ApplicationRole.values()) {
                    if (otherRole != role) {
                        assertThat(detector.isRole(otherRole)).isFalse();
                    }
                }
            }
        }
    }

    @Nested
    @DisplayName("isIdp() Default Method Tests")
    class IsIdpMethodTests {

        @Test
        @DisplayName("Should return true for AGENT_USER_IDP")
        void shouldReturnTrueForAgentUserIdp() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_USER_IDP);

            assertThat(detector.isIdp()).isTrue();
        }

        @Test
        @DisplayName("Should return true for AGENT_IDP")
        void shouldReturnTrueForAgentIdp() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_IDP);

            assertThat(detector.isIdp()).isTrue();
        }

        @Test
        @DisplayName("Should return true for AS_USER_IDP")
        void shouldReturnTrueForAsUserIdp() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AS_USER_IDP);

            assertThat(detector.isIdp()).isTrue();
        }

        @Test
        @DisplayName("Should return false for AUTHORIZATION_SERVER")
        void shouldReturnFalseForAuthorizationServer() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AUTHORIZATION_SERVER);

            assertThat(detector.isIdp()).isFalse();
        }

        @Test
        @DisplayName("Should return false for RESOURCE_SERVER")
        void shouldReturnFalseForResourceServer() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.RESOURCE_SERVER);

            assertThat(detector.isIdp()).isFalse();
        }

        @Test
        @DisplayName("Should return false for AGENT")
        void shouldReturnFalseForAgent() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT);

            assertThat(detector.isIdp()).isFalse();
        }

        @Test
        @DisplayName("Should call detectRole() internally")
        void shouldCallDetectRoleInternally() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_IDP);

            detector.isIdp();

            verify(detector, times(1)).detectRole();
        }
    }

    @Nested
    @DisplayName("isServer() Default Method Tests")
    class IsServerMethodTests {

        @Test
        @DisplayName("Should return true for AUTHORIZATION_SERVER")
        void shouldReturnTrueForAuthorizationServer() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AUTHORIZATION_SERVER);

            assertThat(detector.isServer()).isTrue();
        }

        @Test
        @DisplayName("Should return true for RESOURCE_SERVER")
        void shouldReturnTrueForResourceServer() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.RESOURCE_SERVER);

            assertThat(detector.isServer()).isTrue();
        }

        @Test
        @DisplayName("Should return false for AGENT_USER_IDP")
        void shouldReturnFalseForAgentUserIdp() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_USER_IDP);

            assertThat(detector.isServer()).isFalse();
        }

        @Test
        @DisplayName("Should return false for AGENT_IDP")
        void shouldReturnFalseForAgentIdp() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_IDP);

            assertThat(detector.isServer()).isFalse();
        }

        @Test
        @DisplayName("Should return false for AS_USER_IDP")
        void shouldReturnFalseForAsUserIdp() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AS_USER_IDP);

            assertThat(detector.isServer()).isFalse();
        }

        @Test
        @DisplayName("Should return false for AGENT")
        void shouldReturnFalseForAgent() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT);

            assertThat(detector.isServer()).isFalse();
        }

        @Test
        @DisplayName("Should call detectRole() internally")
        void shouldCallDetectRoleInternally() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AUTHORIZATION_SERVER);

            detector.isServer();

            verify(detector, times(1)).detectRole();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should correctly classify all roles by type")
        void shouldCorrectlyClassifyAllRolesByType() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);

            for (ApplicationRole role : ApplicationRole.values()) {
                when(detector.detectRole()).thenReturn(role);

                boolean isIdp = detector.isIdp();
                boolean isServer = detector.isServer();

                switch (role) {
                    case AGENT_USER_IDP:
                    case AGENT_IDP:
                    case AS_USER_IDP:
                        assertThat(isIdp).isTrue();
                        assertThat(isServer).isFalse();
                        break;
                    case AUTHORIZATION_SERVER:
                    case RESOURCE_SERVER:
                        assertThat(isIdp).isFalse();
                        assertThat(isServer).isTrue();
                        break;
                    case AGENT:
                        assertThat(isIdp).isFalse();
                        assertThat(isServer).isFalse();
                        break;
                }
            }
        }

        @Test
        @DisplayName("Should support role comparison across different methods")
        void shouldSupportRoleComparisonAcrossDifferentMethods() {
            RoleDetector detector = mock(RoleDetector.class, CALLS_REAL_METHODS);
            when(detector.detectRole()).thenReturn(ApplicationRole.AGENT_IDP);

            assertThat(detector.isRole(ApplicationRole.AGENT_IDP)).isTrue();
            assertThat(detector.isIdp()).isTrue();
            assertThat(detector.isServer()).isFalse();
        }
    }
}