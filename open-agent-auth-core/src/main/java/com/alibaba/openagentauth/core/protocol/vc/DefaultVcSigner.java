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
package com.alibaba.openagentauth.core.protocol.vc;

import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.vc.jwt.JwtVcEncoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link VcSigner} for signing Verifiable Credentials.
 * <p>
 * This implementation supports both RSA and ECDSA algorithms to sign Verifiable Credentials
 * and convert them to JWT format. The signer uses a private key (RSA or EC) for signing
 * and includes the key ID in the JWT header for verification.
 * </p>
 * <p>
 * <b>Supported Algorithms:</b>
 * <ul>
 *   <li>RS256/RS384/RS512 - RSA signatures</li>
 *   <li>ES256/ES384/ES512 - ECDSA signatures</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class DefaultVcSigner implements VcSigner {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultVcSigner.class);

    /**
     * The signing key (RSA or EC) used for signing.
     */
    private final JWK signingKey;

    /**
     * The key ID included in the JWT header.
     */
    private final String keyId;

    /**
     * The issuer identifier included in the JWT.
     */
    private final String issuer;

    /**
     * Creates a new DefaultVcSigner with RSA key.
     *
     * @param signingKey the RSA private key for signing
     * @param keyId the key ID to include in the JWT header
     * @param issuer the issuer identifier
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public DefaultVcSigner(RSAKey signingKey, String keyId, String issuer) {
        this((JWK) signingKey, keyId, issuer);
    }

    /**
     * Creates a new DefaultVcSigner with generic JWK.
     *
     * @param signingKey the signing key (RSA or EC) for signing
     * @param keyId the key ID to include in the JWT header
     * @param issuer the issuer identifier
     * @throws IllegalArgumentException if any parameter is invalid
     */
    public DefaultVcSigner(JWK signingKey, String keyId, String issuer) {

        // Validate parameters and initialize
        this.signingKey = ValidationUtils.validateNotNull(signingKey, "Signing key");
        this.keyId = ValidationUtils.validateNotNull(keyId, "Key ID");
        this.issuer = ValidationUtils.validateNotNull(issuer, "Issuer");
        
        logger.info("DefaultVcSigner initialized with keyId: {}, issuer: {}, keyType: {}", 
                keyId, issuer, signingKey.getKeyType());
    }

    /**
     * Signs a Verifiable Credential and returns the signed JWT.
     *
     * @param credential the Verifiable Credential to sign
     * @return the signed JWT
     * @throws JOSEException if signing fails
     */
    @Override
    public String sign(VerifiableCredential credential) throws JOSEException {

        // Validate parameters
        ValidationUtils.validateNotNull(credential, "Credential");
        logger.debug("Signing VerifiableCredential with jti: {}", credential.getJti());
        
        return JwtVcEncoder.encodeAndSign(credential, signingKey, keyId);
    }

    /**
     * Gets the key ID.
     *
     * @return the key ID
     */
    @Override
    public String getKeyId() {
        return keyId;
    }

    /**
     * Gets the issuer.
     *
     * @return the issuer
     */
    @Override
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the signing key.
     *
     * @return the signing key (RSA or EC)
     */
    public JWK getSigningKey() {
        return signingKey;
    }
}