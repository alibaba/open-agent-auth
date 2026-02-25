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
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Controller for JSON Web Key Set (JWKS) endpoint.
 * <p>
 * This controller provides the JWKS endpoint at /.well-known/jwks.json,
 * which returns the public keys in JWKS format for verifying token signatures.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Configurable endpoint path via {@code open-agent-auth.jwks-endpoints.provider.path}</li>
 *   <li>HTTP caching support via Cache-Control headers</li>
 *   <li>Supports multiple signing keys (RSA, ECDSA)</li>
 *   <li>Automatic key rotation support via KeyManager</li>
 * </ul>
 * <p>
 * <b>Note:</b> This controller is registered as a {@code @Bean} by
 * {@link com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration CoreAutoConfiguration}
 * rather than via component scanning, so that the JWKS provider enabled flag set by
 * the role-aware inference logic (which runs after {@code @ConfigurationProperties} binding)
 * is correctly evaluated at bean-creation time.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">OpenID Connect Discovery</a>
 * @see OpenAgentAuthProperties
 * @see KeyManager
 * @since 1.0
 */
@RestController
public class JwksController {

    /**
     * The logger for the JWKS controller.
     */
    private final Logger logger = LoggerFactory.getLogger(JwksController.class);

    /**
     * The configuration properties.
     */
    private final OpenAgentAuthProperties properties;

    /**
     * The key manager for retrieving active keys.
     */
    private final KeyManager keyManager;

    /**
     * Creates a new JWKS controller.
     *
     * @param properties the configuration properties
     * @param keyManager the key manager for retrieving active keys
     */
    public JwksController(
            OpenAgentAuthProperties properties,
            KeyManager keyManager
    ) {
        this.properties = properties;
        this.keyManager = keyManager;
    }

    /**
     * JWKS endpoint.
     * <p>
     * Returns the public keys in JWKS format with appropriate caching headers.
     * Retrieves active keys from KeyManager and converts them to JWK format.
     * </p>
     *
     * @return the JSON Web Key Set with caching headers
     */
    @GetMapping("${open-agent-auth.infrastructures.jwks.provider.path:/.well-known/jwks.json}")
    public ResponseEntity<Map<String, Object>> jwks() {

        // Retrieve active keys from KeyManager
        List<JWK> keys = new ArrayList<>();
        List<KeyInfo> activeKeys = keyManager.getActiveKeys();
        
        // Convert each active key to JWK format
        for (KeyInfo keyInfo : activeKeys) {
            try {
                PublicKey publicKey = keyManager.getVerificationKey(keyInfo.getKeyId());
                JWK jwk = convertPublicKeyToJWK(publicKey, keyInfo);
                keys.add(jwk);
            } catch (Exception e) {
                // Log error but continue with other keys
                // Skip invalid keys rather than failing the entire endpoint
                logger.warn("Failed to convert public key to JWK", e);
            }
        }

        // Build response with caching headers if enabled
        ResponseEntity.BodyBuilder responseBuilder = ResponseEntity.ok();
        
        if (properties.getInfrastructures().getJwks().getProvider() != null 
                && properties.getInfrastructures().getJwks().getProvider().isCacheHeadersEnabled()) {
            CacheControl cacheControl = CacheControl
                    .maxAge(properties.getInfrastructures().getJwks().getProvider().getCacheDurationSeconds(), TimeUnit.SECONDS)
                    .cachePublic();
            responseBuilder.cacheControl(cacheControl);
        }

        // Return JWK Set
        JWKSet jwkSet = new JWKSet(keys);
        return responseBuilder.body(jwkSet.toJSONObject());
    }
    
    /**
     * Converts a PublicKey to JWK format.
     *
     * @param publicKey the public key to convert
     * @param keyInfo the key metadata
     * @return the JWK representation
     */
    private JWK convertPublicKeyToJWK(PublicKey publicKey, KeyInfo keyInfo) {

        // Convert RSA public key to JWK
        if (publicKey instanceof RSAPublicKey) {
            return new RSAKey.Builder((RSAPublicKey) publicKey)
                    .keyID(keyInfo.getKeyId())
                    .algorithm(keyInfo.getAlgorithm().getJwsAlgorithm())
                    .build();
        }

        // Convert EC public key to JWK
        if (publicKey instanceof ECPublicKey ecPublicKey) {
            Curve curve = Curve.forECParameterSpec(ecPublicKey.getParams());
            return new ECKey.Builder(curve, ecPublicKey)
                    .keyID(keyInfo.getKeyId())
                    .algorithm(keyInfo.getAlgorithm().getJwsAlgorithm())
                    .build();
        }

        // Unsupported public key type
        throw new IllegalArgumentException("Unsupported public key type: " + publicKey.getClass().getName());
    }
}