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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.store;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link OAuth2DcrClientStore}.
 * <p>
 * This implementation stores client registration information in memory using
 * concurrent hash maps. It is suitable for testing and development environments.
 * For production use, consider using a persistent storage implementation.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and uses ConcurrentHashMap for storage.
 * </p>
 *
 * @since 1.0
 */
public class InMemoryOAuth2DcrClientStore implements OAuth2DcrClientStore {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(InMemoryOAuth2DcrClientStore.class);

    /**
     * Map of client_id to DcrResponse.
     */
    private final Map<String, DcrResponse> clients;

    /**
     * Map of client_id to registration access token.
     */
    private final Map<String, String> tokens;

    /**
     * Map of registration access token to client_id.
     */
    private final Map<String, String> tokenToClientId;

    /**
     * Map of client_id to DcrRequest.
     */
    private final Map<String, DcrRequest> requests;

    /**
     * Creates a new InMemoryDcrClientStore.
     */
    public InMemoryOAuth2DcrClientStore() {
        this.clients = new ConcurrentHashMap<>();
        this.tokens = new ConcurrentHashMap<>();
        this.tokenToClientId = new ConcurrentHashMap<>();
        this.requests = new ConcurrentHashMap<>();
        
        logger.info("InMemoryDcrClientStore initialized");
    }

    @Override
    public void store(String clientId, String registrationAccessToken, DcrRequest request, DcrResponse response) {
        logger.debug("Storing client registration for client_id: {}", clientId);
        
        clients.put(clientId, response);
        tokens.put(clientId, registrationAccessToken);
        tokenToClientId.put(registrationAccessToken, clientId);
        requests.put(clientId, request);
    }

    @Override
    public DcrResponse retrieve(String clientId) {
        logger.debug("Retrieving client registration for client_id: {}", clientId);
        return clients.get(clientId);
    }

    @Override
    public DcrResponse retrieveByToken(String registrationAccessToken) {
        logger.debug("Retrieving client registration by token");
        String clientId = tokenToClientId.get(registrationAccessToken);
        if (clientId == null) {
            logger.warn("No client found for registration access token");
            return null;
        }
        return clients.get(clientId);
    }

    @Override
    public void update(String clientId, DcrRequest request, DcrResponse response) {
        logger.debug("Updating client registration for client_id: {}", clientId);
        
        if (!clients.containsKey(clientId)) {
            logger.warn("Attempted to update non-existent client: {}", clientId);
            return;
        }
        
        clients.put(clientId, response);
        requests.put(clientId, request);
    }

    @Override
    public void delete(String clientId) {
        logger.debug("Deleting client registration for client_id: {}", clientId);
        
        String registrationAccessToken = tokens.remove(clientId);
        if (registrationAccessToken != null) {
            tokenToClientId.remove(registrationAccessToken);
        }
        
        clients.remove(clientId);
        requests.remove(clientId);
    }

    @Override
    public boolean exists(String clientId) {
        return clients.containsKey(clientId);
    }

    @Override
    public boolean validateToken(String clientId, String registrationAccessToken) {
        String storedToken = tokens.get(clientId);
        return storedToken != null && storedToken.equals(registrationAccessToken);
    }

    /**
     * Clears all stored client registrations.
     * <p>
     * This method is primarily intended for testing purposes.
     * </p>
     */
    public void clear() {
        logger.info("Clearing all client registrations");
        clients.clear();
        tokens.clear();
        tokenToClientId.clear();
        requests.clear();
    }

    /**
     * Gets the number of stored clients.
     *
     * @return the number of stored clients
     */
    public int size() {
        return clients.size();
    }

    @Override
    public DcrResponse retrieveByClientName(String clientName) {
        logger.debug("Retrieving client registration by client_name: {}", clientName);
        
        if (ValidationUtils.isNullOrEmpty(clientName)) {
            return null;
        }
        
        // Iterate through all clients to find matching client_name
        for (Map.Entry<String, DcrResponse> entry : clients.entrySet()) {
            DcrResponse response = entry.getValue();
            if (response != null && clientName.equals(response.getClientName())) {
                logger.debug("Found client by client_name: {} -> client_id: {}", clientName, entry.getKey());
                return response;
            }
        }
        
        logger.warn("No client found with client_name: {}", clientName);
        return null;
    }
}