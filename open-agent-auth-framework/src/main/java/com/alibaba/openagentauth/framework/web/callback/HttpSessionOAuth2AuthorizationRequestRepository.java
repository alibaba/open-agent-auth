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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link OAuth2AuthorizationRequestRepository}.
 * <p>
 * This implementation stores authorization requests in a thread-safe {@link ConcurrentHashMap},
 * keyed by the opaque state parameter. It is suitable for single-server deployments and
 * serves as the default repository when no custom implementation is provided.
 * </p>
 *
 * <h3>Design Notes</h3>
 * <p>
 * Unlike the previous approach of encoding flow type and session ID into the state parameter,
 * this repository stores all authorization metadata server-side, keeping the state parameter
 * as a pure opaque CSRF token per RFC 6749 Section 10.12.
 * </p>
 *
 * <h3>Limitations</h3>
 * <ul>
 *   <li>Not suitable for distributed/clustered deployments — use a Redis or database-backed
 *       implementation instead</li>
 *   <li>Authorization requests are lost on server restart</li>
 *   <li>No automatic expiration — consider implementing periodic cleanup for production use</li>
 * </ul>
 *
 * @since 1.1
 * @see OAuth2AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public class HttpSessionOAuth2AuthorizationRequestRepository implements OAuth2AuthorizationRequestRepository {

    private static final Logger logger = LoggerFactory.getLogger(HttpSessionOAuth2AuthorizationRequestRepository.class);

    private final Map<String, OAuth2AuthorizationRequest> requestStore = new ConcurrentHashMap<>();

    @Override
    public void save(OAuth2AuthorizationRequest authorizationRequest) {
        Objects.requireNonNull(authorizationRequest, "authorizationRequest cannot be null");
        String state = authorizationRequest.getState();
        requestStore.put(state, authorizationRequest);
        logger.debug("Saved authorization request with state: {}, flowType: {}",
                state, authorizationRequest.getFlowType());
    }

    @Override
    public OAuth2AuthorizationRequest load(String state) {
        if (state == null) {
            return null;
        }
        OAuth2AuthorizationRequest request = requestStore.get(state);
        if (request != null) {
            logger.debug("Loaded authorization request for state: {}, flowType: {}",
                    state, request.getFlowType());
        } else {
            logger.debug("No authorization request found for state: {}", state);
        }
        return request;
    }

    @Override
    public OAuth2AuthorizationRequest remove(String state) {
        if (state == null) {
            return null;
        }
        OAuth2AuthorizationRequest removed = requestStore.remove(state);
        if (removed != null) {
            logger.debug("Removed authorization request for state: {}, flowType: {}",
                    state, removed.getFlowType());
        } else {
            logger.debug("No authorization request to remove for state: {}", state);
        }
        return removed;
    }
}
