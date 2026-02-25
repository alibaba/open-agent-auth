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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyManagementProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDiscoveryProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Infrastructure configuration properties for the Open Agent Auth framework.
 * <p>
 * This class defines the infrastructure-level configuration shared across all roles,
 * including trust domain, key management, JWKS, and service discovery.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link OpenAgentAuthProperties} and bound as part of
 * the {@code open-agent-auth.infrastructures} prefix through the parent class.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     trust-domain: wimse://default.trust.domain
 *     key-management:
 *       providers:
 *         in-memory:
 *           type: in-memory
 *           config:
 *             key-size: 2048
 *       keys:
 *         signing-key:
 *           provider: in-memory
 *           algorithm: RS256
 *           purpose: signing
 *     jwks:
 *       provider:
 *         enabled: true
 *         path: /.well-known/jwks.json
 *       consumers:
 *         agent-idp:
 *           jwks-endpoint: http://agent-idp:8081/.well-known/jwks.json
 *     service-discovery:
 *       enabled: true
 *       services:
 *         authorization-server:
 *           url: http://authorization-server:8085
 * </pre>
 *
 * @since 2.0
 * @see KeyManagementProperties
 * @see JwksInfrastructureProperties
 * @see ServiceDiscoveryProperties
 */
public class InfrastructureProperties {

    /**
     * The trust domain for workload identity management.
     * <p>
     * This defines the trust boundary for workload identities.
     * All workloads within the same trust domain can verify each other's identities.
     * Workloads from different trust domains require explicit trust establishment.
     * </p>
     * <p>
     * The trust domain follows the WIMSE (Workload Identity Management for Service Ecosystems)
     * specification format: {@code wimse://<domain-name>}
     * </p>
     * <p>
     * Default: {@code wimse://default.trust.domain}
     * </p>
     */
    private String trustDomain = "wimse://default.trust.domain";

    /**
     * Key management configuration.
     * <p>
     * This configuration defines how cryptographic keys are managed, including:
     * <ul>
     *   <li>Key providers (in-memory)</li>
     *   <li>Key definitions (algorithm, purpose, provider)</li>
     *   <li>Key rotation policies</li>
     * </ul>
     * </p>
     * <p>
     * Keys are used for signing JWTs, encrypting sensitive data, and verifying
     * tokens from other services within the trust domain.
     * </p>
     */
    @NestedConfigurationProperty
    private KeyManagementProperties keyManagement = new KeyManagementProperties();

    /**
     * JWKS (JSON Web Key Set) configuration.
     * <p>
     * This configuration controls how public keys are exposed and how external
     * JWKS endpoints are consumed for token verification:
     * <ul>
     *   <li><b>Provider</b>: Exposes this service's public keys via JWKS endpoint</li>
     *   <li><b>Consumers</b>: Fetches public keys from external services for verification</li>
     * </ul>
     * </p>
     * <p>
     * JWKS is used for verifying JWT signatures from other services in the trust domain.
     * </p>
     */
    @NestedConfigurationProperty
    private JwksInfrastructureProperties jwks = new JwksInfrastructureProperties();

    /**
     * Service discovery configuration.
     * <p>
     * This configuration enables automatic discovery of other services within
     * the trust domain, allowing services to dynamically locate and communicate
     * with each other without hardcoding URLs.
     * </p>
     * <p>
     * Service discovery is particularly useful in microservice environments where
     * service instances may be dynamically scaled or relocated.
     * </p>
     */
    @NestedConfigurationProperty
    private ServiceDiscoveryProperties serviceDiscovery = new ServiceDiscoveryProperties();

    /**
     * Gets the trust domain for workload identity management.
     * <p>
     * The trust domain defines the security boundary within which workloads
     * can verify each other's identities.
     * </p>
     *
     * @return the trust domain URI in WIMSE format
     */
    public String getTrustDomain() {
        return trustDomain;
    }

    /**
     * Sets the trust domain for workload identity management.
     * <p>
     * All workloads within the same trust domain can verify each other's identities.
     * Workloads from different trust domains require explicit trust establishment.
     * </p>
     *
     * @param trustDomain the trust domain URI in WIMSE format (e.g., {@code wimse://default.trust.domain})
     */
    public void setTrustDomain(String trustDomain) {
        this.trustDomain = trustDomain;
    }

    /**
     * Gets the key management configuration.
     * <p>
     * This configuration defines how cryptographic keys are managed, including
     * key providers, key definitions, and rotation policies.
     * </p>
     *
     * @return the key management properties
     */
    public KeyManagementProperties getKeyManagement() {
        return keyManagement;
    }

    /**
     * Sets the key management configuration.
     * <p>
     * This configuration controls how cryptographic keys are provisioned,
     * stored, and rotated for signing and encryption operations.
     * </p>
     *
     * @param keyManagement the key management properties
     */
    public void setKeyManagement(KeyManagementProperties keyManagement) {
        this.keyManagement = keyManagement;
    }

    /**
     * Gets the JWKS configuration.
     * <p>
     * This configuration controls how public keys are exposed for verification
     * and how external JWKS endpoints are consumed.
     * </p>
     *
     * @return the JWKS infrastructure properties
     */
    public JwksInfrastructureProperties getJwks() {
        return jwks;
    }

    /**
     * Sets the JWKS configuration.
     * <p>
     * This configuration defines the JWKS endpoint for exposing public keys
     * and the list of external JWKS endpoints to consume for token verification.
     * </p>
     *
     * @param jwks the JWKS infrastructure properties
     */
    public void setJwks(JwksInfrastructureProperties jwks) {
        this.jwks = jwks;
    }

    /**
     * Gets the service discovery configuration.
     * <p>
     * This configuration enables automatic discovery of other services within
     * the trust domain.
     * </p>
     *
     * @return the service discovery properties
     */
    public ServiceDiscoveryProperties getServiceDiscovery() {
        return serviceDiscovery;
    }

    /**
     * Sets the service discovery configuration.
     * <p>
     * This configuration defines how services are discovered and resolved
     * within the trust domain for inter-service communication.
     * </p>
     *
     * @param serviceDiscovery the service discovery properties
     */
    public void setServiceDiscovery(ServiceDiscoveryProperties serviceDiscovery) {
        this.serviceDiscovery = serviceDiscovery;
    }
}