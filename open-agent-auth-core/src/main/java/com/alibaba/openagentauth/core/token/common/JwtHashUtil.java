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
package com.alibaba.openagentauth.core.token.common;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for computing JWT hashes.
 * <p>
 * This class provides methods to compute SHA-256 hashes of JWT strings,
 * which are commonly used in token binding scenarios such as:
 * </p>
 * <ul>
 *   <li>WIT hash (wth) in Workload Proof Tokens</li>
 *   <li>Access Token hash (ath) in OAuth 2.0</li>
 *   <li>Transaction Token hash (tth)</li>
 *   <li>AOAT hash in WPT oth claim</li>
 * </ul>
 * <p>
 * According to WIMSE specification, the hash is computed as:
 * {@code BASE64URL(SHA-256(ASCII(token_string)))}
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession</a>
 */
public class JwtHashUtil {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(JwtHashUtil.class);

    /**
     * Computes the SHA-256 hash of a JWT string.
     * <p>
     * The hash is computed using the following steps:
     * <ol>
     *   <li>Convert the JWT string to ASCII bytes</li>
     *   <li>Compute SHA-256 hash of the bytes</li>
     *   <li>Encode the hash using Base64URL encoding without padding</li>
     * </ol>
     * </p>
     *
     * @param jwtString the JWT string to hash
     * @return the base64url-encoded SHA-256 hash
     * @throws IllegalArgumentException if the JWT string is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available (should never happen)
     */
    public static String computeSha256Hash(String jwtString) {

        // Validate input
        if (ValidationUtils.isNullOrEmpty(jwtString)) {
            throw new IllegalArgumentException("JWT string cannot be null or empty");
        }

        try {
            // Get SHA-256 message digest
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            // Compute hash of the JWT string
            byte[] hash = digest.digest(jwtString.getBytes(StandardCharsets.UTF_8));
            
            // Encode using Base64URL without padding
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            
        } catch (NoSuchAlgorithmException e) {
            // This should never happen as SHA-256 is required by Java specification
            logger.error("SHA-256 algorithm not available - this should never happen", e);
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Computes the WIT hash (wth) as per WIMSE specification.
     * <p>
     * This is a convenience method that delegates to {@link #computeSha256Hash(String)}.
     * It is specifically named for clarity when computing WIT hashes.
     * </p>
     *
     * @param witJwtString the Workload Identity Token (JWT string)
     * @return the base64url-encoded SHA-256 hash of the WIT
     * @throws IllegalArgumentException if the WIT JWT string is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeWitHash(String witJwtString) {
        return computeSha256Hash(witJwtString);
    }

    /**
     * Computes the Access Token hash (ath) as per RFC 9449.
     * <p>
     * This is a convenience method that delegates to {@link #computeSha256Hash(String)}.
     * It is specifically named for clarity when computing access token hashes.
     * </p>
     *
     * @param accessToken the OAuth access token
     * @return the base64url-encoded SHA-256 hash of the access token
     * @throws IllegalArgumentException if the access token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeAccessTokenHash(String accessToken) {
        return computeSha256Hash(accessToken);
    }

    /**
     * Computes the Transaction Token hash (tth).
     * <p>
     * This is a convenience method that delegates to {@link #computeSha256Hash(String)}.
     * It is specifically named for clarity when computing transaction token hashes.
     * </p>
     *
     * @param transactionToken the transaction token
     * @return the base64url-encoded SHA-256 hash of the transaction token
     * @throws IllegalArgumentException if the transaction token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeTransactionTokenHash(String transactionToken) {
        return computeSha256Hash(transactionToken);
    }

    /**
     * Computes the Agent Operation Authorization Token hash (aoat).
     * <p>
     * This is a convenience method that delegates to {@link #computeSha256Hash(String)}.
     * It is specifically named for clarity when computing AOAT hashes, which are used
     * in the WPT oth (other tokens hashes) claim to bind the WPT to an AOAT token.
     * </p>
     * <p>
     * According to WIMSE specification, the AOAT hash in the oth claim allows the WPT
     * to be cryptographically bound to an AOAT token, ensuring that the workload
     * presenting the WPT also possesses the corresponding AOAT authorization.
     * </p>
     *
     * @param aoatToken the Agent Operation Authorization Token (JWT string)
     * @return the base64url-encoded SHA-256 hash of the AOAT token
     * @throws IllegalArgumentException if the AOAT token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt</a>
     */
    public static String computeAoatHash(String aoatToken) {
        return computeSha256Hash(aoatToken);
    }

    // Private constructor to prevent instantiation
    private JwtHashUtil() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
}