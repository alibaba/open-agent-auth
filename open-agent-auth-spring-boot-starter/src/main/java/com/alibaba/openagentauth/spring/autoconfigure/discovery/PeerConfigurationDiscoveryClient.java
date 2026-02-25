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
package com.alibaba.openagentauth.spring.autoconfigure.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Client for discovering peer service configuration via the
 * {@code /.well-known/oaa-configuration} endpoint.
 * <p>
 * <b>Note:</b> This class is currently a <em>reserved component</em> for future use.
 * It is not yet integrated into the configuration inference pipeline
 * ({@link RoleAwareEnvironmentPostProcessor}). The current peer configuration relies
 * on static YAML declarations (via {@code open-agent-auth.peers}). In a future release,
 * this client will be used to dynamically discover peer capabilities at startup,
 * enabling zero-configuration peer integration.
 * </p>
 * <p>
 * This client implements a robust discovery mechanism with:
 * <ul>
 *   <li><b>Retry with exponential backoff</b>: Retries failed requests up to
 *       {@value #MAX_RETRIES} times with exponentially increasing delays</li>
 *   <li><b>Fail-fast mode</b>: When enabled, throws an exception on discovery
 *       failure to prevent the application from starting with incomplete configuration</li>
 *   <li><b>Caching</b>: Caches successful discovery results to avoid redundant requests</li>
 *   <li><b>Timeout</b>: Configurable connection and request timeouts</li>
 * </ul>
 *
 * @since 2.1
 * @see RoleAwareEnvironmentPostProcessor
 */
public class PeerConfigurationDiscoveryClient {

    private static final Logger logger = LoggerFactory.getLogger(PeerConfigurationDiscoveryClient.class);

    private static final String OAA_CONFIGURATION_PATH = "/.well-known/oaa-configuration";
    private static final int MAX_RETRIES = 3;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final long INITIAL_BACKOFF_MS = 500;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final boolean failFast;
    private final Map<String, Map<String, Object>> cache;

    /**
     * Creates a new discovery client.
     *
     * @param failFast if true, throws an exception when discovery fails;
     *                 if false, logs a warning and returns null
     */
    public PeerConfigurationDiscoveryClient(boolean failFast) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
        this.objectMapper = new ObjectMapper();
        this.failFast = failFast;
        this.cache = new ConcurrentHashMap<>();
    }

    /**
     * Discovers the OAA configuration metadata from a peer service.
     *
     * @param peerName the logical name of the peer (for logging)
     * @param issuer   the issuer URL of the peer service
     * @return the metadata as a map, or null if discovery failed and failFast is false
     * @throws IllegalStateException if discovery fails and failFast is true
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> discover(String peerName, String issuer) {
        Objects.requireNonNull(peerName, "peerName must not be null");
        Objects.requireNonNull(issuer, "issuer must not be null");

        Map<String, Object> cached = cache.get(issuer);
        if (cached != null) {
            logger.debug("Using cached OAA configuration for peer '{}' (issuer: {})", peerName, issuer);
            return cached;
        }

        String discoveryUrl = issuer.endsWith("/")
                ? issuer.substring(0, issuer.length() - 1) + OAA_CONFIGURATION_PATH
                : issuer + OAA_CONFIGURATION_PATH;

        logger.info("Discovering OAA configuration for peer '{}' from: {}", peerName, discoveryUrl);

        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(discoveryUrl))
                        .timeout(REQUEST_TIMEOUT)
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    Map<String, Object> metadata = objectMapper.readValue(response.body(), Map.class);
                    cache.put(issuer, metadata);
                    logger.info("Successfully discovered OAA configuration for peer '{}' "
                            + "(protocol_version: {}, roles: {})",
                            peerName,
                            metadata.get("protocol_version"),
                            metadata.get("roles"));
                    return metadata;
                }

                if (response.statusCode() == 404) {
                    logger.debug("Peer '{}' does not expose OAA configuration endpoint (404). "
                            + "Falling back to explicit configuration.", peerName);
                    return null;
                }

                logger.warn("OAA configuration discovery for peer '{}' returned HTTP {} (attempt {}/{})",
                        peerName, response.statusCode(), attempt, MAX_RETRIES);

            } catch (IOException e) {
                logger.warn("OAA configuration discovery for peer '{}' failed (attempt {}/{}): {}",
                        peerName, attempt, MAX_RETRIES, e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("OAA configuration discovery for peer '{}' was interrupted", peerName);
                break;
            }

            if (attempt < MAX_RETRIES) {
                long backoffMs = INITIAL_BACKOFF_MS * (1L << (attempt - 1));
                logger.debug("Retrying in {} ms...", backoffMs);
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        String errorMessage = String.format(
                "Failed to discover OAA configuration for peer '%s' from %s after %d attempts. "
                + "Ensure the peer is running and accessible, or provide explicit configuration "
                + "under 'open-agent-auth.infrastructures'.",
                peerName, discoveryUrl, MAX_RETRIES);

        if (failFast) {
            throw new IllegalStateException(errorMessage);
        }

        logger.warn("{} Falling back to explicit configuration.", errorMessage);
        return null;
    }

    /**
     * Clears the discovery cache.
     */
    public void clearCache() {
        cache.clear();
    }
}
