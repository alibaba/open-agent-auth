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
package com.alibaba.openagentauth.core.protocol.oidc.api;

import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;

/**
 * Interface for validating OpenID Connect ID Tokens.
 * <p>
 * This interface defines the contract for validating ID Tokens according to the
 * OpenID Connect Core 1.0 specification. Implementations are responsible for
 * verifying the token signature, checking claims, and ensuring the token is valid.
 * </p>
 * <p>
 * <b>Validation Steps:</b></p>
 * <ul>
 *   <li><b>Signature Verification:</b> Verify the token signature using the issuer's public key</li>
 *   <li><b>Issuer Validation:</b> Verify the iss claim matches the expected issuer</li>
 *   <li><b>Audience Validation:</b> Verify the aud claim contains the client ID</li>
 *   <li><b>Expiration Validation:</b> Verify the token has not expired</li>
 *   <li><b>Issued At Validation:</b> Verify the token was issued in the past</li>
 *   <li><b>Nonce Validation:</b> Verify the nonce matches if provided</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST verify the token signature</li>
 *   <li>MUST validate all required claims</li>
 *   <li>MUST reject expired tokens</li>
 *   <li>MUST reject tokens with invalid issuers or audiences</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect Core 1.0 - ID Token Validation</a>
 * @since 1.0
 */
public interface IdTokenValidator {

    /**
     * Validates an ID Token.
     * <p>
     * This method performs comprehensive validation of the ID Token, including
     * signature verification, claims validation, and timing checks.
     * </p>
     * <p>
     * <b>Validation Checks:</b></p>
     * <ol>
     *   <li>Verify the token signature</li>
     *   <li>Verify the issuer (iss claim)</li>
     *   <li>Verify the audience (aud claim)</li>
     *   <li>Verify the token has not expired (exp claim)</li>
     *   <li>Verify the token was issued in the past (iat claim)</li>
     *   <li>Verify the nonce if provided (nonce claim)</li>
     * </ol>
     *
     * @param token the ID token to validate
     * @param expectedIssuer the expected issuer value
     * @param expectedAudience the expected audience value (typically the client ID)
     * @param expectedNonce the expected nonce value, or null if nonce validation is not required
     * @return the validated ID token with parsed claims
     * @throws IdTokenException if validation fails
     * @throws IllegalArgumentException if token, expectedIssuer, or expectedAudience is null
     */
    IdToken validate(String token, String expectedIssuer, String expectedAudience, String expectedNonce);

    /**
     * Validates an ID Token without nonce validation.
     * <p>
     * This method is a convenience method for cases where nonce validation is not required.
     * </p>
     *
     * @param token the ID token to validate
     * @param expectedIssuer the expected issuer value
     * @param expectedAudience the expected audience value
     * @return the validated ID token with parsed claims
     * @throws IdTokenException if validation fails
     * @throws IllegalArgumentException if token, expectedIssuer, or expectedAudience is null
     */
    IdToken validate(String token, String expectedIssuer, String expectedAudience);

    /**
     * Validates an ID Token object.
     * <p>
     * This method validates an already parsed ID Token object.
     * </p>
     *
     * @param idToken the ID token object to validate
     * @param expectedIssuer the expected issuer value
     * @param expectedAudience the expected audience value
     * @param expectedNonce the expected nonce value, or null if nonce validation is not required
     * @return the validated ID token
     * @throws IdTokenException if validation fails
     * @throws IllegalArgumentException if idToken, expectedIssuer, or expectedAudience is null
     */
    IdToken validate(IdToken idToken, String expectedIssuer, String expectedAudience, String expectedNonce);

}
