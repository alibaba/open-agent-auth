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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for OpenID Connect Discovery endpoint.
 * <p>
 * This controller provides the OIDC Discovery endpoint at /.well-known/openid-configuration,
 * which returns the authorization server's configuration metadata according to OpenID Connect Discovery 1.0.
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnExpression("'${open-agent-auth.roles.agent-user-idp.enabled:false}' == 'true' or '${open-agent-auth.roles.as-user-idp.enabled:false}' == 'true'")
public class DiscoveryController {

    private static final Logger logger = LoggerFactory.getLogger(DiscoveryController.class);

    /**
     * The configuration properties.
     */
    private final OpenAgentAuthProperties properties;

    /**
     * The key manager for dynamically resolving active signing algorithms.
     */
    private final KeyManager keyManager;

    /**
     * Creates a new Discovery controller.
     *
     * @param properties the configuration properties
     * @param keyManager the key manager for resolving active signing algorithms
     */
    public DiscoveryController(OpenAgentAuthProperties properties, KeyManager keyManager) {
        this.properties = properties;
        this.keyManager = keyManager;
        logger.info("DiscoveryController initialized with dynamic signing algorithm support");
    }

    /**
     * OIDC Discovery endpoint.
     * <p>
     * Returns the authorization server's configuration metadata.
     * </p>
     *
     * @return the discovery configuration
     */
    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> discovery() {

        // Get issuer from roles configuration
        String issuer = null;
        var agentUserIdpRole = properties.getRole(ConfigConstants.ROLE_AGENT_USER_IDP);
        var asUserIdpRole = properties.getRole(ConfigConstants.ROLE_AS_USER_IDP);
        if (agentUserIdpRole != null && agentUserIdpRole.getIssuer() != null) {
            issuer = agentUserIdpRole.getIssuer();
        } else if (asUserIdpRole != null && asUserIdpRole.getIssuer() != null) {
            issuer = asUserIdpRole.getIssuer();
        }
        
        if (issuer == null) {
            issuer = "https://default.issuer";
        }

        // Build discovery configuration per OIDC Discovery 1.0
        Map<String, Object> config = new HashMap<>();
        config.put("issuer", issuer);

        // OAuth2 endpoints (conditional on OAuth2 Server capability)
        if (properties.getCapabilities().getOAuth2Server().isEnabled()) {
            var oauth2Endpoints = properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2();
            config.put("authorization_endpoint", issuer + oauth2Endpoints.getAuthorize());
            config.put("token_endpoint", issuer + oauth2Endpoints.getToken());
            config.put("pushed_authorization_request_endpoint", issuer + oauth2Endpoints.getPar());
        }

        // OIDC endpoints (REQUIRED per OIDC Discovery 1.0 Section 3)
        config.put("jwks_uri", issuer + "/.well-known/jwks.json");
        config.put("userinfo_endpoint", issuer + properties.getCapabilities().getOAuth2Server()
                .getEndpoints().getOauth2().getUserinfo());
        config.put("revocation_endpoint", issuer + "/oauth2/revoke");

        // Response types (REQUIRED per OIDC Discovery 1.0 Section 3)
        config.put("response_types_supported", List.of("code"));

        // Grant types (OPTIONAL but recommended)
        config.put("grant_types_supported", List.of("authorization_code", "client_credentials"));

        // Subject types (REQUIRED per OIDC Discovery 1.0 Section 3)
        config.put("subject_types_supported", List.of("public"));

        // ID Token signing algorithms (REQUIRED per OIDC Discovery 1.0 Section 3)
        // Dynamically resolved from active keys in KeyManager
        config.put("id_token_signing_alg_values_supported", resolveActiveSigningAlgorithms());

        // Scopes (RECOMMENDED per OIDC Discovery 1.0 Section 3)
        config.put("scopes_supported", List.of("openid", "profile", "email"));

        // Token endpoint auth methods (OPTIONAL)
        config.put("token_endpoint_auth_methods_supported", List.of("private_key_jwt", "client_secret_basic"));

        // Claims (RECOMMENDED per OIDC Discovery 1.0 Section 3)
        config.put("claims_supported", List.of(
                "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "name", "email", "preferred_username"));

        // PKCE support (RFC 7636)
        config.put("code_challenge_methods_supported", List.of("S256"));

        return config;
    }

    /**
     * Resolves the list of active signing algorithms from the KeyManager.
     * <p>
     * This method queries the KeyManager for all active keys and extracts their
     * algorithm names. If no active keys are found, it falls back to {@code ["RS256"]}
     * as the default, ensuring the discovery document always declares at least one
     * supported algorithm.
     * </p>
     *
     * @return the list of supported signing algorithm names
     */
    private List<String> resolveActiveSigningAlgorithms() {
        try {
            List<KeyInfo> activeKeys = keyManager.getActiveKeys();
            if (activeKeys != null && !activeKeys.isEmpty()) {
                List<String> algorithms = activeKeys.stream()
                        .map(keyInfo -> keyInfo.getAlgorithm().name())
                        .distinct()
                        .collect(Collectors.toList());
                logger.debug("Resolved active signing algorithms: {}", algorithms);
                return algorithms;
            }
        } catch (Exception e) {
            logger.warn("Failed to resolve active signing algorithms, falling back to default: {}", e.getMessage());
        }
        return List.of("RS256");
    }
}