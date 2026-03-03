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
package com.alibaba.openagentauth.core.protocol.oauth2.token.revocation;

/**
 * Service for token revocation according to RFC 7009.
 * <p>
 * This service provides operations to revoke tokens and check their revocation status.
 * Token revocation is used to invalidate tokens that are no longer needed or have been
 * compromised, allowing clients to explicitly request the revocation of access tokens
 * and refresh tokens.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7009">RFC 7009 - OAuth 2.0 Token Revocation</a>
 * @since 1.0
 */
public interface TokenRevocationService {

    /**
     * Revokes the specified token.
     * <p>
     * Once a token is revoked, it should not be accepted by the authorization server
     * for any further requests. The revocation is idempotent - revoking an already
     * revoked token has no additional effect.
     * </p>
     * <p>
     * <b>Note:</b> Per RFC 7009 Section 2.1, the authorization server MUST respond with
     * HTTP 200 (OK) regardless of whether the token was valid, invalid, or already revoked.
     * </p>
     *
     * @param token the token string to revoke (access token or refresh token)
     */
    void revoke(String token);

    /**
     * Checks whether the specified token has been revoked.
     * <p>
     * This method is used by resource servers and other components to verify
     * if a token has been explicitly revoked before accepting it.
     * </p>
     *
     * @param token the token string to check
     * @return {@code true} if the token has been revoked, {@code false} otherwise
     */
    boolean isRevoked(String token);
}
