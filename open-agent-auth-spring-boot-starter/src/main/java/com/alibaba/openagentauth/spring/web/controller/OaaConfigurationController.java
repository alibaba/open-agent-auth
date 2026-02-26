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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants;
import com.alibaba.openagentauth.spring.autoconfigure.properties.DefaultEndpoints;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RoleProfile;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RoleProfileRegistry;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import com.alibaba.openagentauth.spring.web.model.OaaConfigurationMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * OAA Configuration Discovery Controller.
 * <p>
 * Exposes the {@code /.well-known/oaa-configuration} endpoint that returns
 * metadata about this service instance, including its role, capabilities,
 * supported algorithms, and required peers.
 * </p>
 * <p>
 * This endpoint enables automatic service discovery and capability negotiation
 * between peers in the Open Agent Auth trust domain, following a design inspired
 * by OIDC Discovery but tailored for multi-role agent authorization.
 * </p>
 *
 * @since 2.1
 * @see OaaConfigurationMetadata
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "open-agent-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class OaaConfigurationController {

    private static final Logger logger = LoggerFactory.getLogger(OaaConfigurationController.class);

    /**
     * Well-known path for OAA configuration metadata.
     */
    public static final String OAA_WELL_KNOWN_PATH = ConfigConstants.OAA_CONFIGURATION_PATH;

    private final OpenAgentAuthProperties properties;

    public OaaConfigurationController(OpenAgentAuthProperties properties) {
        this.properties = properties;
    }

    /**
     * Returns the OAA configuration metadata for this service instance.
     *
     * @return the configuration metadata with appropriate caching headers
     */
    @GetMapping(value = OAA_WELL_KNOWN_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OaaConfigurationMetadata> getConfiguration() {
        OaaConfigurationMetadata metadata = buildMetadata();

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(5, TimeUnit.MINUTES).cachePublic())
                .body(metadata);
    }

    /**
     * Builds the OAA configuration metadata by aggregating information from
     * enabled roles, their profiles, and the current infrastructure configuration.
     */
    private OaaConfigurationMetadata buildMetadata() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();

        // Determine enabled roles and their issuer
        List<String> enabledRoles = new ArrayList<>();
        String issuer = null;
        for (Map.Entry<String, RolesProperties.RoleProperties> entry : properties.getRoles().entrySet()) {
            if (entry.getValue().isEnabled()) {
                enabledRoles.add(entry.getKey());
                if (issuer == null && entry.getValue().getIssuer() != null) {
                    issuer = entry.getValue().getIssuer();
                }
            }
        }

        metadata.setIssuer(issuer);
        metadata.setRoles(enabledRoles);
        metadata.setTrustDomain(properties.getTrustDomain());
        metadata.setProtocolVersion(OaaConfigurationMetadata.CURRENT_PROTOCOL_VERSION);

        // JWKS URI
        if (issuer != null) {
            metadata.setJwksUri(issuer + ConfigConstants.JWKS_WELL_KNOWN_PATH);
        }

        // Collect signing algorithms from role profiles
        Set<String> algorithms = new LinkedHashSet<>();
        Set<String> peersRequired = new LinkedHashSet<>();
        for (String roleName : enabledRoles) {
            RoleProfile profile = RoleProfileRegistry.getProfile(roleName);
            if (profile != null) {
                for (String keyName : profile.getSigningKeys()) {
                    String algorithm = profile.getDefaultAlgorithm(keyName);
                    if (algorithm != null) {
                        algorithms.add(algorithm);
                    }
                }
                peersRequired.addAll(profile.getRequiredPeers());
            }
        }
        metadata.setSigningAlgorithmsSupported(new ArrayList<>(algorithms));
        metadata.setPeersRequired(new ArrayList<>(peersRequired));

        // Capabilities
        Map<String, Object> capabilities = buildCapabilities();
        if (!capabilities.isEmpty()) {
            metadata.setCapabilities(capabilities);
        }

        // Endpoints
        Map<String, String> endpoints = buildEndpoints(issuer);
        if (!endpoints.isEmpty()) {
            metadata.setEndpoints(endpoints);
        }

        return metadata;
    }

    /**
     * Builds the capabilities map from enabled capability configurations.
     * Each enabled capability is represented as a map entry with its status.
     */
    private Map<String, Object> buildCapabilities() {
        Map<String, Object> capabilities = new LinkedHashMap<>();
        var caps = properties.getCapabilities();

        if (caps.getWorkloadIdentity() != null && caps.getWorkloadIdentity().isEnabled()) {
            capabilities.put("workload_identity", Map.of("enabled", true));
        }
        if (caps.getOAuth2Server() != null && caps.getOAuth2Server().isEnabled()) {
            capabilities.put("oauth2_server", Map.of("enabled", true));
        }
        if (caps.getOAuth2Client() != null && caps.getOAuth2Client().isEnabled()) {
            capabilities.put("oauth2_client", Map.of("enabled", true));
        }
        if (caps.getOperationAuthorization() != null && caps.getOperationAuthorization().isEnabled()) {
            capabilities.put("operation_authorization", Map.of("enabled", true));
        }
        if (caps.getUserAuthentication() != null && caps.getUserAuthentication().isEnabled()) {
            capabilities.put("user_authentication", Map.of("enabled", true));
        }
        if (caps.getAudit() != null && caps.getAudit().isEnabled()) {
            capabilities.put("audit", Map.of("enabled", true));
        }

        return capabilities;
    }

    /**
     * Builds the endpoints map by combining the issuer URL with default endpoint paths.
     *
     * @param issuer the issuer URL to use as base, or null if no issuer is configured
     * @return map of endpoint names to full URLs, or empty map if issuer is null
     */
    private Map<String, String> buildEndpoints(String issuer) {
        if (issuer == null) {
            return Map.of();
        }

        Map<String, String> endpoints = new LinkedHashMap<>();
        Map<String, String> defaults = DefaultEndpoints.getAllDefaults();

        for (Map.Entry<String, String> entry : defaults.entrySet()) {
            endpoints.put(entry.getKey(), issuer + entry.getValue());
        }

        return endpoints;
    }
}