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
 * Parses and processes OAuth2 state parameters to determine the authorization flow type.
 * The state parameter format depends on the flow type:
 * </p>
 * <ul>
 *   <li><b>User Authentication:</b> {@code user:{random}} — session managed via HTTP cookies</li>
 *   <li><b>Agent Operation Authorization:</b> {@code agent:{random}:{sessionId}} — session ID
 *       embedded in state for cross-domain session restoration</li>
 * </ul>
 * <p>
 * The state parameter serves two purposes per RFC 6749 Section 10.12:
 * </p>
 * <ul>
 *   <li><b>CSRF protection:</b> The random component prevents cross-site request forgery attacks</li>
 *   <li><b>Flow routing:</b> The prefix component determines which callback flow to execute</li>
 * </ul>
 *
 * @since 1.0
 */
public class OAuth2StateHandler {

    private static final String STATE_PREFIX_USER_AUTHENTICATION = "user";
    private static final String STATE_PREFIX_AGENT_OPERATION_AUTH = "agent";
    private static final String STATE_SEPARATOR = ":";

    /**
     * Parse state parameter to determine the authorization flow type.
     * <p>
     * The state parameter format varies by flow:
     * </p>
     * <ul>
     *   <li>User Authentication: {@code user:{random}} — no sessionId</li>
     *   <li>Agent Operation Authorization: {@code agent:{random}:{sessionId}} — sessionId for cross-domain restore</li>
     * </ul>
     *
     * @param state state parameter string
     * @return parsed StateInfo containing the flow type, original state, and optional sessionId
     */
    public StateInfo parse(String state) {
        if (ValidationUtils.isNullOrEmpty(state)) {
            return StateInfo.unknown();
        }

        // Extract flow type prefix (before the first colon)
        int firstSeparatorIndex = state.indexOf(STATE_SEPARATOR);
        if (firstSeparatorIndex < 0) {
            return StateInfo.unknown();
        }

        String flowType = state.substring(0, firstSeparatorIndex);
        FlowType resolvedFlowType = determineFlowType(flowType);

        // For Agent Operation Authorization flow, extract sessionId from the third segment
        String sessionId = null;
        if (resolvedFlowType == FlowType.AGENT_OPERATION_AUTH) {
            String remainder = state.substring(firstSeparatorIndex + 1);
            int secondSeparatorIndex = remainder.indexOf(STATE_SEPARATOR);
            if (secondSeparatorIndex >= 0) {
                sessionId = remainder.substring(secondSeparatorIndex + 1);
                if (sessionId.isEmpty()) {
                    sessionId = null;
                }
            }
        }

        return StateInfo.builder()
                .flowType(resolvedFlowType)
                .originalState(state)
                .sessionId(sessionId)
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
     * State information containing the parsed flow type, original state string,
     * and optional sessionId (only for Agent Operation Authorization flow).
     */
    public static class StateInfo {
        private final FlowType flowType;
        private final String originalState;
        private final String sessionId;

        private StateInfo(FlowType flowType, String originalState, String sessionId) {
            this.flowType = flowType;
            this.originalState = originalState;
            this.sessionId = sessionId;
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

        public String getOriginalState() {
            return originalState;
        }

        /**
         * Returns the session ID extracted from the state parameter.
         * Only populated for Agent Operation Authorization flow where cross-domain
         * session restoration is needed.
         *
         * @return the session ID, or null if not applicable
         */
        public String getSessionId() {
            return sessionId;
        }

        /**
         * StateInfo builder.
         */
        public static class StateInfoBuilder {
            private FlowType flowType;
            private String originalState;
            private String sessionId;

            public StateInfoBuilder flowType(FlowType flowType) {
                this.flowType = flowType;
                return this;
            }

            public StateInfoBuilder originalState(String originalState) {
                this.originalState = originalState;
                return this;
            }

            public StateInfoBuilder sessionId(String sessionId) {
                this.sessionId = sessionId;
                return this;
            }

            public StateInfo build() {
                return new StateInfo(flowType, originalState, sessionId);
            }
        }
    }
}
