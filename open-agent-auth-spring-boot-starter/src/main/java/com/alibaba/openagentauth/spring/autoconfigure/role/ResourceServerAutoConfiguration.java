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
package com.alibaba.openagentauth.spring.autoconfigure.role;

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.binding.RemoteBindingInstanceStore;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.policy.evaluator.LightweightPolicyEvaluator;
import com.alibaba.openagentauth.core.policy.registry.RemotePolicyRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.trust.model.TrustAnchor;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.framework.orchestration.DefaultResourceServer;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Auto-configuration for Resource Server role.
 * <p>
 * This configuration provides automatic setup for the Resource Server role,
 * which hosts protected resources and implements the five-layer validation architecture.
 * </p>
 * <p>
 * <b>Role Identification:</b></p>
 * <p>
 * Enable this configuration by setting:
 * </p>
 * <pre>
 * open-agent-auth:
 *     role: resource-server
 * </pre>
 * <p>
 * This role is typically used in scenarios where:
 * </p>
 * <ul>
 *   <li>Your application hosts protected resources that need to be accessed by AI Agents</li>
 *   <li>You need to validate Agent OA Tokens and WITs for access control</li>
 *   <li>You want to implement fine-grained access control for AI Agent operations</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *     enabled: true
 *     role: resource-server
 *     trust-domain: wimse://example.trust.domain
 *     jwks:
 *       enabled: false
 *       consumers:
 *         agent-idp:
 *           enabled: true
 *           jwks-endpoint: https://agent-idp.example.com/.well-known/jwks.json
 *           issuer: https://agent-idp.example.com
 *         authorization-server:
 *           enabled: true
 *           jwks-endpoint: https://authorization-server.example.com/.well-known/jwks.json
 *           issuer: https://authorization-server.example.com
 *     resource-server:
 *       enabled: true
 *       agent-idp:
 *         audience: https://resource-server.example.com
 *         clock-skew-seconds: 60
 *       authorization-server:
 *         audience: https://resource-server.example.com
 *         clock-skew-seconds: 60
 * </pre>
 * <p>
 * <b>Provided Beans:</b></p>
 * <ul>
 *   <li><code>witValidator</code>: WIT validator for Layer 1 validation</li>
 *   <li><code>wptValidator</code>: WPT validator for Layer 1.5 validation</li>
 *   <li><code>policyEvaluator</code>: Policy evaluator for Layer 4 validation</li>
 *   <li><code>resourceServer</code>: Resource Server implementation</li>
 *   <li><code>agentAuthenticationInterceptor</code>: Authentication interceptor for protecting endpoints</li>
 * </ul>
 *
 * @see CoreAutoConfiguration
 * @see AgentIdpAutoConfiguration
 * @see AuthorizationServerAutoConfiguration
 * @since 1.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth.roles.resource-server", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class ResourceServerAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(ResourceServerAutoConfiguration.class);

    /**
     * Creates a WitValidator bean that uses the correct verification key from Agent IDP.
     * <p>
     * This bean uses @Primary to override the default WitValidator bean from
     * ResourceServerAutoConfiguration. It specifically looks for the 'wit-verification-key'
     * in the JWKS endpoint instead of using the first key.
     * </p>
     *
     * @return the WitValidator
     */
    @Bean
    @ConditionalOnMissingBean
    public WitValidator witValidator(OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating WitValidator bean for Resource Server");
        String agentIdpJwksEndpoint = openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().get("agent-idp").getJwksEndpoint();
        String witKeyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("wit-verification").getKeyId();
        try {
            // Load the public key from the JWKS endpoint
            JWKSet jwkSet = JWKSet.load(new URL(agentIdpJwksEndpoint));

            // Find the configured WIT key specifically, not just the first key
            ECKey witSigningKey = null;
            for (JWK jwk : jwkSet.getKeys()) {
                if (jwk.getKeyID() != null && jwk.getKeyID().equals(witKeyId)) {
                    if (jwk instanceof ECKey ecKey) {
                        witSigningKey = ecKey;
                        break;
                    }
                }
            }

            if (witSigningKey == null) {
                throw new IllegalStateException(
                        "WIT verification key '" + witKeyId + "' not found in Agent IDP JWKS endpoint. Available keys: " +
                                jwkSet.getKeys().stream()
                                        .map(k -> k.getKeyID() != null ? k.getKeyID() : "null")
                                        .toList()
                );
            }

            logger.info("Found wit-signing-key in Agent IDP JWKS endpoint: keyId={}, algorithm={}, curve={}",
                    witSigningKey.getKeyID(),
                    witSigningKey.getAlgorithm(),
                    witSigningKey.getCurve());

            // Create TrustDomain from infrastructure configuration
            String trustDomain = openAgentAuthProperties.getInfrastructures().getTrustDomain();
            TrustDomain trustDomainObj = new TrustDomain(trustDomain);

            // Create TrustAnchor with the EC public key from Agent IDP
            // WIT uses algorithm configured in YAML (default: ES256)
            String witAlgorithm = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("wit-verification").getAlgorithm();
            KeyAlgorithm keyAlgorithm = KeyAlgorithm.valueOf(witAlgorithm);
            TrustAnchor trustAnchor;
            try {
                trustAnchor = new TrustAnchor(
                        witSigningKey.toPublicKey(),
                        witSigningKey.getKeyID(),
                        keyAlgorithm,
                        trustDomainObj
                );
            } catch (Exception e) {
                throw new IllegalStateException("Failed to convert ECKey to PublicKey", e);
            }

            logger.info("Created TrustAnchor: keyId={}, algorithm={}, trustDomain={}",
                    trustAnchor.getKeyId(),
                    trustAnchor.getAlgorithm(),
                    trustAnchor.getTrustDomain().getDomainId());

            // Create WitValidator with TrustAnchor
            return new WitValidator(trustAnchor);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create WitValidator for Resource Server", e);
        }
    }

    /**
     * Creates an AoatValidator bean that uses the correct verification key from Authorization Server.
     * <p>
     * This bean uses @Primary to override the default AoatValidator bean from
     * ResourceServerAutoConfiguration. It specifically looks for the 'aoat-signing-key'
     * in the JWKS endpoint instead of using the first RSA key.
     * </p>
     *
     * @return the AoatValidator
     */
    @Bean
    @ConditionalOnMissingBean
    public AoatValidator aoatValidator(OpenAgentAuthProperties openAgentAuthProperties) {
        logger.info("Creating AoatValidator bean for Resource Server");

        String authorizationServerJwksEndpoint = openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().get("authorization-server").getJwksEndpoint();
        String aoatKeyId = openAgentAuthProperties.getInfrastructures().getKeyManagement().getKeys().get("aoat-verification").getKeyId();
        try {
            // Load the public key from the JWKS endpoint
            JWKSet jwkSet = JWKSet.load(new URL(authorizationServerJwksEndpoint));

            // Find the configured AOAT key specifically, not just the first RSA key
            RSAKey aoatSigningKey = null;
            for (JWK jwk : jwkSet.getKeys()) {
                if (jwk.getKeyID() != null && jwk.getKeyID().equals(aoatKeyId)) {
                    if (jwk instanceof RSAKey rsaKey) {
                        aoatSigningKey = rsaKey;
                        break;
                    }
                }
            }

            if (aoatSigningKey == null) {
                throw new IllegalStateException(
                        "AOAT verification key '" + aoatKeyId + "' not found in Authorization Server JWKS endpoint. Available keys: " +
                                jwkSet.getKeys().stream()
                                        .map(k -> k.getKeyID() != null ? k.getKeyID() : "null")
                                        .toList()
                );
            }

            logger.info("Found aoat-verification-key in Authorization Server JWKS endpoint: keyId={}, algorithm={}",
                    aoatSigningKey.getKeyID(),
                    aoatSigningKey.getAlgorithm());

            // Create AoatValidator with the correct verification key, issuer, and audience
            String authorizationServerIssuer = openAgentAuthProperties.getInfrastructures().getJwks().getConsumers().get("authorization-server").getIssuer();
            
            // Get issuer from roles configuration
            String resourceServerIssuer = null;
            if (openAgentAuthProperties.getRoles() != null) {
                var role = openAgentAuthProperties.getRoles().get("resource-server");
                if (role != null) {
                    resourceServerIssuer = role.getIssuer();
                }
            }
            
            return new AoatValidator(
                    aoatSigningKey,
                    authorizationServerIssuer,
                    resourceServerIssuer
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to create AoatValidator for Resource Server", e);
        }
    }

    /**
     * Creates the WPT Validator bean if not already defined.
     * <p>
     * This validator provides validation for Workload Proof Tokens (WPT).
     * It implements Layer 1.5 validation for request integrity verification.
     * </p>
     *
     * @return the WPT Validator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public WptValidator wptValidator() {
        logger.info("Creating WptValidator bean");
        return new WptValidator();
    }

    /**
     * Creates the ServiceEndpointResolver bean.
     * <p>
     * This resolver is used to resolve service endpoints for different services.
     * </p>
     */
    @Bean
    @ConditionalOnMissingBean
    public ServiceEndpointResolver serviceEndpointResolver(OpenAgentAuthProperties openAgentAuthProperties) {
        // Convert new architecture service discovery to legacy ServiceProperties format
        ServiceProperties serviceProperties = new ServiceProperties();
        
        // Map service discovery services to consumer services
        Map<String, ServiceProperties.ConsumerServiceProperties> consumers = new HashMap<>();
        if (openAgentAuthProperties.getInfrastructures().getServiceDiscovery() != null
                && openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices() != null) {
            openAgentAuthProperties.getInfrastructures().getServiceDiscovery().getServices().forEach((name, service) -> {
                ServiceProperties.ConsumerServiceProperties consumer = new ServiceProperties.ConsumerServiceProperties();
                consumer.setBaseUrl(service.getBaseUrl());
                consumer.setEndpoints(service.getEndpoints());
                consumers.put(name, consumer);
            });
        }
        serviceProperties.setConsumers(consumers);
        
        return new DefaultServiceEndpointResolver(serviceProperties);
    }

    /**
     * Creates the Policy Registry bean if not already defined.
     * <p>
     * This registry provides storage for policies.
     * If the authorization server base URL is configured, it creates a RemotePolicyRegistry
     * that communicates with the Authorization Server's PolicyRegistry REST API.
     * Otherwise, it creates an InMemoryPolicyRegistry for local policy storage.
     * </p>
     *
     * @param serviceEndpointResolver the service endpoint resolver for communicating with Authorization Server
     * @return the Policy Registry bean
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "open-agent-auth.resource-server", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PolicyRegistry policyRegistry(ServiceEndpointResolver serviceEndpointResolver) {
        logger.info("Creating PolicyRegistry bean");

        // Create RemotePolicyRegistry for communicating with Authorization Server
        return new RemotePolicyRegistry(serviceEndpointResolver);
    }

    /**
     * Creates the Policy Evaluator bean if not already defined.
     * <p>
     * This evaluator provides policy evaluation for fine-grained access control.
     * It implements Layer 4 validation.
     * </p>
     *
     * @param policyRegistry the policy registry
     * @return the Policy Evaluator bean
     */
    @Bean
    @ConditionalOnMissingBean
    public PolicyEvaluator policyEvaluator(PolicyRegistry policyRegistry) {
        logger.info("Creating PolicyEvaluator bean");
        return new LightweightPolicyEvaluator(policyRegistry);
    }

    /**
     * Creates the Resource Server bean if not already defined.
     * <p>
     * This server provides resource access control with five-layer validation architecture:
     * </p>
     * <ul>
     *   <li>Layer 1: Validate WIT signature (workload authentication)</li>
     *   <li>Layer 2: Validate WPT signature (request integrity)</li>
     *   <li>Layer 3: Validate Agent OA Token (user authentication)</li>
     *   <li>Layer 4: Validate identity consistency (user == workload)</li>
     *   <li>Layer 5: OPA policy evaluation (fine-grained authorization)</li>
     * </ul>
     *
     * @param witValidator the WIT validator for Layer 1 validation
     * @param wptValidator the WPT validator for Layer 2 validation
     * @param aoatValidator the AOAT validator for Layer 3 validation
     * @param policyEvaluator the policy evaluator for Layer 5 validation
     * @param bindingInstanceStore the binding instance store for two-layer verification
     * @return the Resource Server bean
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultResourceServer resourceServer(
            WitValidator witValidator,
            WptValidator wptValidator,
            AoatValidator aoatValidator,
            PolicyEvaluator policyEvaluator,
            BindingInstanceStore bindingInstanceStore) {
        logger.info("Creating DefaultResourceServer bean");

        return new DefaultResourceServer(
                witValidator,
                wptValidator,
                aoatValidator,
                policyEvaluator,
                bindingInstanceStore
        );
    }

    /**
     * Creates a RemoteBindingInstanceStore bean for querying binding instances from the Authorization Server.
     *
     * @param serviceEndpointResolver the service endpoint resolver for communicating with Authorization Server
     * @return the RemoteBindingInstanceStore
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "open-agent-auth.resource-server", name = "enabled", havingValue = "true", matchIfMissing = true)
    public BindingInstanceStore bindingInstanceStore(ServiceEndpointResolver serviceEndpointResolver) {
        return new RemoteBindingInstanceStore(serviceEndpointResolver);
    }
}