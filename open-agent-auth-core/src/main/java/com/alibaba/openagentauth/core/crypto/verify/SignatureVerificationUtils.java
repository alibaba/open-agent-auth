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
package com.alibaba.openagentauth.core.crypto.verify;

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for JWT signature verification.
 * <p>
 * Centralizes the common signature verification logic shared across
 * {@code WitValidator}, {@code AoatValidator}, and {@code DefaultIdTokenValidator}.
 * This eliminates code duplication and provides a single point of maintenance
 * for verification key resolution and verifier creation.
 * </p>
 * <p>
 * The verification flow:
 * <ol>
 *   <li>Resolve the verification key from {@link KeyManager} by key ID</li>
 *   <li>Create the appropriate {@link JWSVerifier} based on key type (RSA or EC)</li>
 *   <li>Verify the JWT signature</li>
 * </ol>
 * </p>
 *
 * @since 1.0
 */
public final class SignatureVerificationUtils {

    private static final Logger logger = LoggerFactory.getLogger(SignatureVerificationUtils.class);

    private SignatureVerificationUtils() {
        // Utility class, prevent instantiation
    }

    /**
     * Verifies the signature of a signed JWT using the specified {@link KeyManager} and key ID.
     * <p>
     * This method dynamically resolves the verification key from the {@code KeyManager}
     * on each invocation, ensuring that key rotations are picked up without restarts.
     * </p>
     *
     * @param signedJwt the signed JWT to verify
     * @param keyManager the key manager for resolving verification keys
     * @param verificationKeyId the key ID used to resolve the verification key
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    public static boolean verifySignature(SignedJWT signedJwt, KeyManager keyManager, String verificationKeyId) {

        JWSAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();
        String headerKeyId = signedJwt.getHeader().getKeyID();
        logger.debug("Verifying signature - header kid: {}, algorithm: {}, verificationKeyId: {}",
                headerKeyId, algorithm, verificationKeyId);

        if (!isSupportedAlgorithm(algorithm)) {
            logger.warn("Unsupported algorithm: {}", algorithm);
            return false;
        }

        try {
            JWK verificationKey = keyManager.resolveVerificationKey(verificationKeyId);
            JWSVerifier verifier = createVerifier(verificationKey);
            boolean isValid = signedJwt.verify(verifier);

            if (!isValid) {
                logger.warn("Signature verification failed - header kid: {}, verificationKeyId: {}",
                        headerKeyId, verificationKeyId);
            }
            return isValid;
        } catch (KeyManagementException e) {
            logger.error("Failed to resolve verification key for keyId '{}': {}",
                    verificationKeyId, e.getMessage());
            return false;
        } catch (JOSEException e) {
            logger.error("Error during signature verification: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Creates a {@link JWSVerifier} from the given JWK.
     *
     * @param jwk the JWK to create a verifier from
     * @return the created verifier
     * @throws JOSEException if the verifier cannot be created
     * @throws IllegalArgumentException if the JWK type is not supported
     */
    public static JWSVerifier createVerifier(JWK jwk) throws JOSEException {
        if (jwk instanceof RSAKey rsaKey) {
            return new RSASSAVerifier(rsaKey);
        }
        if (jwk instanceof ECKey ecKey) {
            return new ECDSAVerifier(ecKey);
        }
        throw new IllegalArgumentException("Unsupported JWK type: " + jwk.getKeyType());
    }

    /**
     * Checks whether the given JWS algorithm is supported for verification.
     *
     * @param algorithm the JWS algorithm to check
     * @return {@code true} if the algorithm is in the RSA or EC family
     */
    public static boolean isSupportedAlgorithm(JWSAlgorithm algorithm) {
        return JWSAlgorithm.Family.RSA.contains(algorithm) || JWSAlgorithm.Family.EC.contains(algorithm);
    }
}
