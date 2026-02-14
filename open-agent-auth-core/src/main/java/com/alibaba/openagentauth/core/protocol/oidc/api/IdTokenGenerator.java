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
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;

/**
 * Interface for generating OpenID Connect ID Tokens.
 * <p>
 * This interface defines the contract for creating ID Tokens according to the
 * OpenID Connect Core 1.0 specification. Implementations are responsible for
 * signing the token with the appropriate algorithm and including all required claims.
 * </p>
 * <p>
 * <b>Responsibilities:</b></p>
 * <ul>
 *   <li><b>Token Creation:</b> Create a JWT with the specified claims</li>
 *   <li><b>Signing:</b> Sign the token using the configured algorithm</li>
 *   <li><b>Claims Validation:</b> Ensure all required claims are present</li>
 *   <li><b>Token Serialization:</b> Serialize the token to its string representation</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST use a secure signing algorithm (e.g., RS256, ES256)</li>
 *   <li>MUST protect the signing key</li>
 *   <li>MUST include all required claims</li>
 *   <li>MUST set appropriate expiration times</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core 1.0 - ID Token</a>
 * @since 1.0
 */
public interface IdTokenGenerator {

    /**
     * Generates an ID Token from the specified claims.
     * <p>
     * This method creates a signed JWT containing the provided claims. The token
     * will be signed using the configured algorithm and key.
     * </p>
     * <p>
     * <b>Required Claims:</b></p>
     * <ul>
     *   <li><b>iss:</b> Issuer identifier</li>
     *   <li><b>sub:</b> Subject identifier</li>
     *   <li><b>aud:</b> Audience</li>
     *   <li><b>exp:</b> Expiration time</li>
     *   <li><b>iat:</b> Issued at time</li>
     * </ul>
     * <p>
     * <b>Optional Claims:</b></p>
     * <ul>
     *   <li><b>auth_time:</b> Authentication time</li>
     *   <li><b>nonce:</b> Nonce value</li>
     *   <li><b>acr:</b> Authentication Context Class Reference</li>
     *   <li><b>amr:</b> Authentication Methods References</li>
     *   <li><b>azp:</b> Authorized party</li>
     * </ul>
     *
     * @param claims the claims to include in the ID token
     * @return the generated ID token
     * @throws IdTokenException if token generation fails
     * @throws IllegalArgumentException if claims is null or missing required fields
     */
    IdToken generate(IdTokenClaims claims);

    /**
     * Generates an ID Token with the specified expiration time.
     * <p>
     * This method is a convenience method that automatically sets the expiration
     * time based on the specified lifetime in seconds.
     * </p>
     *
     * @param claims the claims to include in the ID token
     * @param lifetimeInSeconds the token lifetime in seconds
     * @return the generated ID token
     * @throws IdTokenException if token generation fails
     * @throws IllegalArgumentException if claims is null or lifetime is invalid
     */
    IdToken generate(IdTokenClaims claims, long lifetimeInSeconds);

}
