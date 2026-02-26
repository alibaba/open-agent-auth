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
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    /**
     * The configuration properties.
     */
    private final OpenAgentAuthProperties properties;

    /**
     * Creates a new Discovery controller.
     *
     * @param properties the configuration properties
     */
    public DiscoveryController(OpenAgentAuthProperties properties) {
        this.properties = properties;
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

        // Create discovery configuration
        Map<String, Object> config = new HashMap<>();
        config.put("issuer", issuer);
        
        // Add PAR endpoint if enabled
        if (properties.getCapabilities().getOAuth2Server().isEnabled()) {
            config.put("pushed_authorization_request_endpoint", issuer + properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2().getPar());
        }
        
        // Add token endpoint if enabled
        if (properties.getCapabilities().getOAuth2Server().isEnabled()) {
            config.put("token_endpoint", issuer + properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2().getToken());
        }
        
        // Add authorization endpoint if enabled
        if (properties.getCapabilities().getOAuth2Server().isEnabled()) {
            config.put("authorization_endpoint", issuer + properties.getCapabilities().getOAuth2Server().getEndpoints().getOauth2().getAuthorize());
        }
        
        // Add JWKS endpoint
        config.put("jwks_uri", issuer + "/.well-known/jwks.json");
        
        // Add standard OIDC claims
        config.put("response_types_supported", List.of("code"));
        config.put("grant_types_supported", List.of("authorization_code", "client_credentials"));
        config.put("subject_types_supported", List.of("public"));
        config.put("id_token_signing_alg_values_supported", List.of("RS256"));
        config.put("scopes_supported", List.of("openid", "profile", "email"));
        config.put("token_endpoint_auth_methods_supported", List.of("private_key_jwt", "client_secret_basic"));
        config.put("claims_supported", List.of("sub", "iss", "aud", "exp", "iat"));

        return config;
    }
}