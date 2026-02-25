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
package com.alibaba.openagentauth.spring.web.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * OAA (Open Agent Auth) Configuration Metadata.
 * <p>
 * This model represents the metadata returned by the {@code /.well-known/oaa-configuration}
 * endpoint. It follows a protocol-level design inspired by OIDC Discovery
 * ({@code /.well-known/openid-configuration}) but tailored for the Open Agent Auth
 * framework's multi-role architecture.
 * </p>
 * <p>
 * The metadata enables automatic service discovery and capability negotiation between
 * peers in the trust domain, significantly reducing manual configuration.
 * </p>
 *
 * <h3>Protocol Versioning</h3>
 * <p>
 * The {@code protocol_version} field follows semantic versioning (e.g., "1.0").
 * Consumers should check this field to ensure compatibility before processing
 * the metadata.
 * </p>
 *
 * @since 2.1
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OaaConfigurationMetadata {

    /**
     * Current protocol version for the OAA configuration metadata format.
     */
    public static final String CURRENT_PROTOCOL_VERSION = "1.0";

    // ==================== Identity ====================

    /**
     * The issuer identifier for this service instance.
     * <p>
     * This MUST be a URL using the https scheme (or http for development)
     * that the service asserts as its Issuer Identifier.
     * </p>
     */
    @JsonProperty("issuer")
    private String issuer;

    /**
     * The role(s) this service instance fulfills.
     * <p>
     * A service may fulfill multiple roles simultaneously (e.g., "agent" + "agent-idp").
     * Valid values: agent, agent-idp, agent-user-idp, as-user-idp,
     * authorization-server, resource-server.
     * </p>
     */
    @JsonProperty("roles")
    private List<String> roles;

    /**
     * The trust domain this service belongs to.
     * <p>
     * Format: {@code wimse://<domain-name>}
     * </p>
     */
    @JsonProperty("trust_domain")
    private String trustDomain;

    // ==================== Protocol ====================

    /**
     * The protocol version of this metadata format.
     * <p>
     * Follows semantic versioning. Consumers should verify compatibility
     * before processing the metadata.
     * </p>
     */
    @JsonProperty("protocol_version")
    private String protocolVersion = CURRENT_PROTOCOL_VERSION;

    // ==================== Key Discovery ====================

    /**
     * URL of the service's JSON Web Key Set (JWKS) document.
     * <p>
     * Contains the public keys used to verify signatures issued by this service.
     * </p>
     */
    @JsonProperty("jwks_uri")
    private String jwksUri;

    /**
     * Signing algorithms supported by this service.
     */
    @JsonProperty("signing_algorithms_supported")
    private List<String> signingAlgorithmsSupported;

    // ==================== Capabilities ====================

    /**
     * The capabilities provided by this service instance.
     * <p>
     * Each entry describes a functional capability and its configuration.
     * This enables capability negotiation between peers.
     * </p>
     */
    @JsonProperty("capabilities")
    private Map<String, Object> capabilities;

    // ==================== Endpoints ====================

    /**
     * Service endpoints exposed by this instance.
     * <p>
     * Maps endpoint names to their full URLs. Standard endpoint names include:
     * workload.issue, oauth2.authorize, oauth2.token, oauth2.par, etc.
     * </p>
     */
    @JsonProperty("endpoints")
    private Map<String, String> endpoints;

    // ==================== Peers ====================

    /**
     * Peer services required by this instance.
     * <p>
     * Lists the role names of services that this instance depends on.
     * Consumers can use this for topology-aware configuration.
     * </p>
     */
    @JsonProperty("peers_required")
    private List<String> peersRequired;

    // ==================== Getters and Setters ====================

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getTrustDomain() {
        return trustDomain;
    }

    public void setTrustDomain(String trustDomain) {
        this.trustDomain = trustDomain;
    }

    public String getProtocolVersion() {
        return protocolVersion;
    }

    public void setProtocolVersion(String protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public List<String> getSigningAlgorithmsSupported() {
        return signingAlgorithmsSupported;
    }

    public void setSigningAlgorithmsSupported(List<String> signingAlgorithmsSupported) {
        this.signingAlgorithmsSupported = signingAlgorithmsSupported;
    }

    public Map<String, Object> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(Map<String, Object> capabilities) {
        this.capabilities = capabilities;
    }

    public Map<String, String> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(Map<String, String> endpoints) {
        this.endpoints = endpoints;
    }

    public List<String> getPeersRequired() {
        return peersRequired;
    }

    public void setPeersRequired(List<String> peersRequired) {
        this.peersRequired = peersRequired;
    }
}
