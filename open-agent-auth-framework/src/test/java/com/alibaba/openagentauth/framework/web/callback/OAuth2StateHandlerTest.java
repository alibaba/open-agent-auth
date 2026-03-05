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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link OAuth2StateHandler}.
 */
@DisplayName("OAuth2StateHandler Tests")
class OAuth2StateHandlerTest {

    private OAuth2StateHandler stateHandler;

    @BeforeEach
    void setUp() {
        stateHandler = new OAuth2StateHandler();
    }

    @Nested
    @DisplayName("parse() - User Authentication Flow")
    class UserAuthenticationFlow {

        @Test
        @DisplayName("Should parse user authentication state")
        void shouldParseUserAuthenticationState() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("user:abc123");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.USER_AUTHENTICATION);
            assertThat(result.getOriginalState()).isEqualTo("user:abc123");
            assertThat(result.getSessionId()).isNull();
        }
    }

    @Nested
    @DisplayName("parse() - Agent Operation Authorization Flow")
    class AgentOperationAuthFlow {

        @Test
        @DisplayName("Should parse agent state with sessionId")
        void shouldParseAgentStateWithSessionId() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("agent:random123:session456");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(result.getOriginalState()).isEqualTo("agent:random123:session456");
            assertThat(result.getSessionId()).isEqualTo("session456");
        }

        @Test
        @DisplayName("Should parse agent state without sessionId segment")
        void shouldParseAgentStateWithoutSessionIdSegment() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("agent:random123");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(result.getOriginalState()).isEqualTo("agent:random123");
            assertThat(result.getSessionId()).isNull();
        }

        @Test
        @DisplayName("Should parse agent state with empty sessionId as null")
        void shouldParseAgentStateWithEmptySessionIdAsNull() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("agent:random123:");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(result.getSessionId()).isNull();
        }
    }

    @Nested
    @DisplayName("parse() - Unknown and Edge Cases")
    class UnknownAndEdgeCases {

        @Test
        @DisplayName("Should return unknown for null state")
        void shouldReturnUnknownForNullState() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse(null);

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
            assertThat(result.getOriginalState()).isNull();
            assertThat(result.getSessionId()).isNull();
        }

        @Test
        @DisplayName("Should return unknown for empty state")
        void shouldReturnUnknownForEmptyState() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
        }

        @Test
        @DisplayName("Should return unknown for state without separator")
        void shouldReturnUnknownForStateWithoutSeparator() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("noseparator");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
        }

        @Test
        @DisplayName("Should return unknown for unrecognized prefix")
        void shouldReturnUnknownForUnrecognizedPrefix() {
            // Act
            OAuth2StateHandler.StateInfo result = stateHandler.parse("unknown:abc123");

            // Assert
            assertThat(result.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
            assertThat(result.getOriginalState()).isEqualTo("unknown:abc123");
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
                    .originalState("agent:random:session")
                    .sessionId("session")
                    .build();

            // Assert
            assertThat(stateInfo.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.AGENT_OPERATION_AUTH);
            assertThat(stateInfo.getOriginalState()).isEqualTo("agent:random:session");
            assertThat(stateInfo.getSessionId()).isEqualTo("session");
        }

        @Test
        @DisplayName("Should create unknown StateInfo via static method")
        void shouldCreateUnknownStateInfoViaStaticMethod() {
            // Act
            OAuth2StateHandler.StateInfo stateInfo = OAuth2StateHandler.StateInfo.unknown();

            // Assert
            assertThat(stateInfo.getFlowType()).isEqualTo(OAuth2StateHandler.FlowType.UNKNOWN);
            assertThat(stateInfo.getOriginalState()).isNull();
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
