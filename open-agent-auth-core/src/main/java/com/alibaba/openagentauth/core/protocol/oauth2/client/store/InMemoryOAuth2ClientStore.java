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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link OAuth2ClientStore}.
 * <p>
 * This lightweight implementation stores OAuth 2.0 client registrations in memory
 * without any DCR-specific functionality. It is suitable for roles that need basic
 * client storage (e.g., IDP roles with predefined clients) but do not require
 * Dynamic Client Registration capabilities.
 * </p>
 * <p>
 * <b>Thread Safety:</b>
 * This implementation is thread-safe and uses {@link ConcurrentHashMap} for storage.
 * </p>
 *
 * @since 1.0
 */
public class InMemoryOAuth2ClientStore implements OAuth2ClientStore {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryOAuth2ClientStore.class);

    private final Map<String, OAuth2RegisteredClient> clients = new ConcurrentHashMap<>();

    public InMemoryOAuth2ClientStore() {
        logger.info("InMemoryOAuth2ClientStore initialized");
    }

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
}
