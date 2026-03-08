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
package com.alibaba.openagentauth.core.protocol.oauth2.client.store;

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Unified in-memory implementation of {@link OAuth2DcrClientStore}.
 * <p>
 * This implementation stores all OAuth 2.0 client registrations — both statically
 * pre-registered clients and dynamically registered (DCR, RFC 7591) clients — in a
 * single in-memory store. By consolidating both client sources into one store, all
 * components that depend on {@link OAuth2ClientStore} (e.g., PAR Controller, Token
 * Controller, Authorization Server) can transparently look up any client regardless
 * of how it was registered.
 * </p>
 * <p>
 * <b>Thread Safety:</b>
 * This implementation is thread-safe and uses {@link ConcurrentHashMap} for storage.
 * </p>
 *
 * @see OAuth2ClientStore
 * @see OAuth2DcrClientStore
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
public class InMemoryOAuth2ClientStore implements OAuth2DcrClientStore {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryOAuth2ClientStore.class);

    /**
     * Primary client storage keyed by client_id.
     * Stores {@link OAuth2RegisteredClient} for all clients (pre-registered and DCR).
     */
    private final Map<String, OAuth2RegisteredClient> clients = new ConcurrentHashMap<>();

    /**
     * DCR response storage keyed by client_id.
     * Only populated for dynamically registered clients.
     */
    private final Map<String, DcrResponse> dcrResponses = new ConcurrentHashMap<>();

    /**
     * DCR request storage keyed by client_id.
     * Only populated for dynamically registered clients.
     */
    private final Map<String, DcrRequest> dcrRequests = new ConcurrentHashMap<>();

    /**
     * Registration access token storage keyed by client_id.
     * Only populated for dynamically registered clients.
     */
    private final Map<String, String> registrationTokens = new ConcurrentHashMap<>();

    /**
     * Reverse mapping from registration access token to client_id.
     * Only populated for dynamically registered clients.
     */
    private final Map<String, String> tokenToClientId = new ConcurrentHashMap<>();

    public InMemoryOAuth2ClientStore() {
        logger.info("InMemoryOAuth2ClientStore initialized");
    }

    // ==================== OAuth2ClientStore Methods ====================

    @Override
    public void register(OAuth2RegisteredClient client) {
        ValidationUtils.validateNotNull(client, "Client");
        String clientId = client.getClientId();
        ValidationUtils.validateNotNull(clientId, "Client ID");

        clients.put(clientId, client);
        logger.debug("Registered client: {}", clientId);
    }

    @Override
    public OAuth2RegisteredClient retrieve(String clientId) {
        if (clientId == null) {
            return null;
        }
        logger.debug("Retrieving client: {}", clientId);
        return clients.get(clientId);
    }

    @Override
    public OAuth2RegisteredClient retrieveByClientName(String clientName) {
        if (ValidationUtils.isNullOrEmpty(clientName)) {
            return null;
        }

        for (OAuth2RegisteredClient client : clients.values()) {
            if (clientName.equals(client.getClientName())) {
                logger.debug("Found client by name: {} -> {}", clientName, client.getClientId());
                return client;
            }
        }

        logger.debug("No client found with name: {}", clientName);
        return null;
    }

    @Override
    public boolean exists(String clientId) {
        if (clientId == null) {
            return false;
        }
        return clients.containsKey(clientId);
    }

    // ==================== OAuth2DcrClientStore Methods ====================

    @Override
    public void store(String clientId, String registrationAccessToken, DcrRequest request, DcrResponse response) {
        logger.debug("Storing DCR client registration for client_id: {}", clientId);

        clients.put(clientId, response.toRegisteredClient());
        dcrResponses.put(clientId, response);
        dcrRequests.put(clientId, request);
        registrationTokens.put(clientId, registrationAccessToken);
        tokenToClientId.put(registrationAccessToken, clientId);
    }

    @Override
    public DcrResponse retrieveDcrResponse(String clientId) {
        logger.debug("Retrieving full DCR response for client_id: {}", clientId);
        return dcrResponses.get(clientId);
    }

    @Override
    public DcrResponse retrieveByToken(String registrationAccessToken) {
        logger.debug("Retrieving client registration by token");
        String clientId = tokenToClientId.get(registrationAccessToken);
        if (clientId == null) {
            logger.warn("No client found for registration access token");
            return null;
        }
        return dcrResponses.get(clientId);
    }

    @Override
    public void update(String clientId, DcrRequest request, DcrResponse response) {
        logger.debug("Updating client registration for client_id: {}", clientId);

        if (!clients.containsKey(clientId)) {
            logger.warn("Attempted to update non-existent client: {}", clientId);
            return;
        }

        clients.put(clientId, response.toRegisteredClient());
        dcrResponses.put(clientId, response);
        dcrRequests.put(clientId, request);
    }

    @Override
    public void delete(String clientId) {
        logger.debug("Deleting client registration for client_id: {}", clientId);

        String registrationAccessToken = registrationTokens.remove(clientId);
        if (registrationAccessToken != null) {
            tokenToClientId.remove(registrationAccessToken);
        }

        clients.remove(clientId);
        dcrResponses.remove(clientId);
        dcrRequests.remove(clientId);
    }

    @Override
    public boolean validateToken(String clientId, String registrationAccessToken) {
        String storedToken = registrationTokens.get(clientId);
        return storedToken != null && storedToken.equals(registrationAccessToken);
    }
}
