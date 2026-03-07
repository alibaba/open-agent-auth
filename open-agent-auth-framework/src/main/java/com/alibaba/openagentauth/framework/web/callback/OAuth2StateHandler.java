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

import com.alibaba.openagentauth.core.model.oauth2.authorization.OAuth2AuthorizationRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;

/**
 * OAuth2 State parameter handler.
 * <p>
 * Resolves authorization flow metadata from an opaque state parameter by looking up
 * the corresponding {@link OAuth2AuthorizationRequest} from an
 * {@link OAuth2AuthorizationRequestStorage}.
 * </p>
 *
 * <h3>Design Change (1.1)</h3>
 * <p>
 * In version 1.0, this class parsed business semantics (flow type prefix, session ID)
 * directly from the state string format ({@code agent:UUID:sessionId}). Starting from
 * version 1.1, the state is treated as an opaque CSRF token per RFC 6749 Section 10.12.
 * All flow metadata is resolved from the server-side {@link OAuth2AuthorizationRequestStorage},
 * following the approach used by Spring Security OAuth2.
 * </p>
 *
 * @since 1.0
 */
public class OAuth2StateHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2StateHandler.class);

    private final OAuth2AuthorizationRequestStorage requestStorage;

    /**
     * Creates a new OAuth2StateHandler with the given authorization request storage.
     *
     * @param requestStorage the storage for resolving authorization requests by state
     */
    public OAuth2StateHandler(OAuth2AuthorizationRequestStorage requestStorage) {
        this.requestStorage = requestStorage;
    }

    /**
     * Resolves the authorization flow metadata for the given state parameter.
     * <p>
     * Looks up the {@link OAuth2AuthorizationRequest} from the repository using the
     * opaque state value. If found, the request is consumed (removed) from the repository
     * to prevent replay attacks. If not found, returns an unknown state info.
     * </p>
     *
     * @param state the opaque state parameter from the authorization callback
     * @return resolved StateInfo containing the flow type, original state, and optional sessionId
     */
    public StateInfo resolve(String state) {
        if (ValidationUtils.isNullOrEmpty(state)) {
            logger.debug("State parameter is null or empty, returning unknown");
            return StateInfo.unknown();
        }

        OAuth2AuthorizationRequest authorizationRequest = requestStorage.remove(state);
        if (authorizationRequest == null) {
            logger.warn("No authorization request found for state: {}", state);
            return StateInfo.unknown();
        }

        OAuth2AuthorizationRequest.FlowType flowType = authorizationRequest.getFlowType();
        logger.debug("Resolved authorization request for state: {}, flowType: {}", state, flowType);

        return StateInfo.builder()
                .flowType(mapFlowType(flowType))
                .originalState(state)
                .sessionId(authorizationRequest.getSessionId())
                .additionalParameters(authorizationRequest.getAdditionalParameters())
                .build();
    }

    /**
     * Maps the {@link OAuth2AuthorizationRequest.FlowType} to the handler's {@link FlowType}.
     *
     * @param requestFlowType the flow type from the authorization request
     * @return the corresponding handler flow type
     */
    private FlowType mapFlowType(OAuth2AuthorizationRequest.FlowType requestFlowType) {
        return switch (requestFlowType) {
            case USER_AUTHENTICATION -> FlowType.USER_AUTHENTICATION;
            case AGENT_OPERATION_AUTH -> FlowType.AGENT_OPERATION_AUTH;
            default -> FlowType.UNKNOWN;
        };
    }

    /**
     * Flow type enum.
     * <p>
     * Defines the type of OAuth 2.0 authorization flow, which determines
     * how the callback response should be processed.
     * </p>
     */
    public enum FlowType {
        USER_AUTHENTICATION,
        AGENT_OPERATION_AUTH,
        UNKNOWN
    }

    /**
     * State information resolved from the {@link OAuth2AuthorizationRequestStorage}.
     * <p>
     * Contains the flow type, original state string, and optional session ID
     * for cross-domain session restoration.
     * </p>
     */
    public static class StateInfo {
        private final FlowType flowType;
        private final String originalState;
        private final String sessionId;
        private final Map<String, Object> additionalParameters;

        private StateInfo(FlowType flowType, String originalState, String sessionId, Map<String, Object> additionalParameters) {
            this.flowType = flowType;
            this.originalState = originalState;
            this.sessionId = sessionId;
            this.additionalParameters = additionalParameters != null ? additionalParameters : Collections.emptyMap();
        }

        public static StateInfo unknown() {
            return new StateInfo(FlowType.UNKNOWN, null, null, null);
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
         * Returns the session ID for cross-domain session restoration.
         * <p>
         * Only populated for Agent Operation Authorization flow where the
         * authorization redirect may cross domain boundaries.
         * </p>
         *
         * @return the session ID, or null if not applicable
         */
        public String getSessionId() {
            return sessionId;
        }

        /**
         * Returns additional parameters from the authorization request.
         * <p>
         * Used to pass metadata such as the DCR-registered client_id
         * through the callback flow.
         * </p>
         *
         * @return an unmodifiable map of additional parameters
         */
        public Map<String, Object> getAdditionalParameters() {
            return additionalParameters;
        }

        /**
         * StateInfo builder.
         */
        public static class StateInfoBuilder {
            private FlowType flowType;
            private String originalState;
            private String sessionId;
            private Map<String, Object> additionalParameters;

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

            public StateInfoBuilder additionalParameters(Map<String, Object> additionalParameters) {
                this.additionalParameters = additionalParameters;
                return this;
            }

            public StateInfo build() {
                return new StateInfo(flowType, originalState, sessionId, additionalParameters);
            }
        }
    }
}
