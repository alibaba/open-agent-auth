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
package com.alibaba.openagentauth.framework.web.callback;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for {@link OAuth2StateHandler}.
 */
@DisplayName("OAuth2StateHandler Tests")
@ExtendWith(MockitoExtension.class)
class OAuth2StateHandlerTest {

    @Mock
    private OAuth2AuthorizationRequestRepository mockRepository;

    private OAuth2StateHandler stateHandler;

    @BeforeEach
    void setUp() {
        stateHandler = new OAuth2StateHandler(mockRepository);
    }

    @Nested
    @DisplayName("resolve() - User Authentication Flow")
    class UserAuthenticationFlow {

        @Test
        @DisplayName("Should resolve user authentication state")
        void shouldResolveUserAuthenticationState() {
            // Arrange
            String state = "opaque-state-1";
            OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.builder()
                    .state(state)
                    .flowType(OAuth2AuthorizationRequest.FlowType.USER_AUTHENTICATION)
                    .build();
            when(mockRepository.remove(state)).thenReturn(request);

            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.resolve(state);

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.USER_AUTHENTICATION);
            assertThat(result.getSessionId()).isNull();
            verify(mockRepository).remove(state);
        }
    }

    @Nested
    @DisplayName("resolve() - Agent Operation Authorization Flow")
    class AgentOperationAuthFlow {

        @Test
        @DisplayName("Should resolve agent operation auth state with sessionId")
        void shouldResolveAgentOperationAuthStateWithSessionId() {
            // Arrange
            String state = "opaque-state-2";
            String sessionId = "session-456";
            OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.builder()
                    .state(state)
                    .flowType(OAuth2AuthorizationRequest.FlowType.AGENT_OPERATION_AUTH)
                    .sessionId(sessionId)
                    .build();
            when(mockRepository.remove(state)).thenReturn(request);

            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.resolve(state);

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(result.getSessionId()).isEqualTo(sessionId);
            verify(mockRepository).remove(state);
        }

        @Test
        @DisplayName("Should resolve agent operation auth state without sessionId")
        void shouldResolveAgentOperationAuthStateWithoutSessionId() {
            // Arrange
            String state = "opaque-state-3";
            OAuth2AuthorizationRequest request = OAuth2AuthorizationRequest.builder()
                    .state(state)
                    .flowType(OAuth2AuthorizationRequest.FlowType.AGENT_OPERATION_AUTH)
                    .build();
            when(mockRepository.remove(state)).thenReturn(request);

            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.resolve(state);

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(result.getSessionId()).isNull();
            verify(mockRepository).remove(state);
        }
    }

    @Nested
    @DisplayName("resolve() - Unknown and Edge Cases")
    class UnknownAndEdgeCases {

        @Test
        @DisplayName("Should return unknown for null state")
        void shouldReturnUnknownForNullState() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.resolve(null);

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
            assertThat(result.getSessionId()).isNull();
        }

        @Test
        @DisplayName("Should return unknown for empty state")
        void shouldReturnUnknownForEmptyState() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.resolve("");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
        }

        @Test
        @DisplayName("Should return unknown when state not found in repository")
        void shouldReturnUnknownWhenStateNotFoundInRepository() {
            // Arrange
            String state = "non-existent-state";
            when(mockRepository.remove(state)).thenReturn(null);

            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.resolve(state);

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
            verify(mockRepository).remove(state);
        }
    }

    @Nested
    @DisplayName("StateInfo Builder Tests")
    class StateInfoBuilderTests {

        @Test
        @DisplayName("Should build StateInfo with all fields")
        void shouldBuildStateInfoWithAllFields() {
            // Act
            OAuth2StateHandler.StateInfo stateInfo = OAuth2StateHandler.StateInfo.builder()
                    .flowType(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH)
                    .sessionId("session")
                    .build();

            // Assert
            assertThat(stateInfo.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(stateInfo.getSessionId()).isEqualTo("session");
        }

        @Test
        @DisplayName("Should create unknown StateInfo via static method")
        void shouldCreateUnknownStateInfoViaStaticMethod() {
            // Act
            OAuth2StateHandler.StateInfo stateInfo = OAuth2StateHandler.StateInfo.unknown();

            // Assert
            assertThat(stateInfo.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
            assertThat(stateInfo.getSessionId()).isNull();
        }
    }

    @Nested
    @DisplayName("FlowType Enum Tests")
    class FlowTypeEnumTests {

        @Test
        @DisplayName("Should have all expected flow types")
        void shouldHaveAllExpectedFlowTypes() {
            // Assert
            assertThat(OAuth2StateHandler.FlowType.values()).containsExactlyInAnyOrder(
                    OAuth2StateHandler.FlowType.USER_AUTHENTICATION,
                    OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH,
                    OAuth2StateHandler.FlowType.UNKNOWN
            );
        }
    }
}