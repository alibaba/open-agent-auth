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

import com.alibaba.openagentauth.core.util.ValidationUtils;

/**
 * OAuth2 State parameter handler.
 * <p>
 * Parses and processes OAuth2 state parameters, supporting different authorization flows.
 * </p>
 *
 * @since 1.0
 */
public class OAuth2StateHandler {

    private static final String STATE_PREFIX_USER_AUTHENTICATION = "user";
    private static final String STATE_PREFIX_AGENT_OPERATION_AUTH = "agent";

    /**
     * Parse state parameter.
     *
     * @param state state parameter string
     * @return parsed StateInfo
     */
    public StateInfo parse(String state) {
        if (ValidationUtils.isNullOrEmpty(state)) {
            return StateInfo.unknown();
        }

        String[] parts = state.split(":");
        if (parts.length < 1) {
            return StateInfo.unknown();
        }

        String flowType = parts[0];
        String sessionId = parts.length >= 3 ? parts[2] : null;

        return StateInfo.builder()
                .flowType(determineFlowType(flowType))
                .sessionId(sessionId)
                .originalState(state)
                .build();
    }

    /**
     * Determine flow type.
     *
     * @param prefix prefix
     * @return flow type
     */
    private FlowType determineFlowType(String prefix) {
        if (STATE_PREFIX_AGENT_OPERATION_AUTH.equals(prefix)) {
            return FlowType.AGENT_OPERATION_AUTH;
        }
        if (STATE_PREFIX_USER_AUTHENTICATION.equals(prefix)) {
            return FlowType.USER_AUTHENTICATION;
        }
        return FlowType.UNKNOWN;
    }

    /**
     * Flow type enum.
     */
    public enum FlowType {
        USER_AUTHENTICATION,
        AGENT_OPERATION_AUTH,
        UNKNOWN
    }

    /**
     * State information.
     */
    public static class StateInfo {
        private final FlowType flowType;
        private final String sessionId;
        private final String originalState;

        private StateInfo(FlowType flowType, String sessionId, String originalState) {
            this.flowType = flowType;
            this.sessionId = sessionId;
            this.originalState = originalState;
        }

        public static StateInfo unknown() {
            return new StateInfo(FlowType.UNKNOWN, null, null);
        }

        public static StateInfoBuilder builder() {
            return new StateInfoBuilder();
        }

        public FlowType getFlowType() {
            return flowType;
        }

        public String getSessionId() {
            return sessionId;
        }

        public String getOriginalState() {
            return originalState;
        }

        /**
         * StateInfo builder.
         */
        public static class StateInfoBuilder {
            private FlowType flowType;
            private String sessionId;
            private String originalState;

            public StateInfoBuilder flowType(FlowType flowType) {
                this.flowType = flowType;
                return this;
            }

            public StateInfoBuilder sessionId(String sessionId) {
                this.sessionId = sessionId;
                return this;
            }

            public StateInfoBuilder originalState(String originalState) {
                this.originalState = originalState;
                return this;
            }

            public StateInfo build() {
                return new StateInfo(flowType, sessionId, originalState);
            }
        }
    }
}
