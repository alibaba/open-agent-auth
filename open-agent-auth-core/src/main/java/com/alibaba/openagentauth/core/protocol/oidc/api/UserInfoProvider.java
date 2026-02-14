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

import com.alibaba.openagentauth.core.model.oidc.UserInfo;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;

/**
 * Interface for providing user information in OpenID Connect.
 * <p>
 * This interface defines the contract for retrieving user information from the
 * UserInfo Endpoint. Implementations are responsible for making authenticated
 * requests to the endpoint and parsing the response.
 * </p>
 * <p>
 * <b>Protocol Flow:</b></p>
 * <pre>
 * Client                                        UserInfo Endpoint
 *  |                                                    |
 *  |-- GET /userinfo (Authorization: Bearer token) --->|
 *  |                                                    |
 *  |<-- 200 OK (application/json) ---------------------|
 *  | {                                                  |
 *  |   "sub": "248289761001",                           |
 *  |   "name": "Jane Doe",                              |
 *  |   "email": "jane.doe@example.com"                 |
 *  | }                                                  |
 * </pre>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST use HTTPS for all requests</li>
 *   <li>MUST authenticate using the access token</li>
 *   <li>MUST validate the response format</li>
 *   <li>MUST handle errors gracefully</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 - UserInfo</a>
 * @since 1.0
 */
public interface UserInfoProvider {

    /**
     * Retrieves user information using the specified access token.
     * <p>
     * This method makes an authenticated request to the UserInfo Endpoint
     * and returns the user information claims.
     * </p>
     * <p>
     * <b>HTTP Request Format:</b></p>
     * <pre>
     * GET /userinfo HTTP/1.1
     * Host: as.example.com
     * Authorization: Bearer [access_token]
     * </pre>
     * <p>
     * <b>HTTP Response Format (Success):</b></p>
     * <pre>
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     *
     * {
     *   "sub": "248289761001",
     *   "name": "Jane Doe",
     *   "given_name": "Jane",
     *   "family_name": "Doe",
     *   "email": "jane.doe@example.com",
     *   "email_verified": true
     * }
     * </pre>
     * <p>
     * <b>HTTP Response Format (Error):</b></p>
     * <pre>
     * HTTP/1.1 401 Unauthorized
     * WWW-Authenticate: Bearer error="invalid_token"
     * </pre>
     *
     * @param accessToken the access token for authentication
     * @return the user information
     * @throws IdTokenException if the request fails or the response is invalid
     * @throws IllegalArgumentException if accessToken is null or empty
     */
    UserInfo getUserInfo(String accessToken);

    /**
     * Retrieves user information with the specified subject identifier.
     * <p>
     * This method allows filtering the user information by subject identifier.
     * This is useful when the UserInfo Endpoint supports multiple users.
     * </p>
     *
     * @param accessToken the access token for authentication
     * @param subject the subject identifier to filter by
     * @return the user information
     * @throws IdTokenException if the request fails or the response is invalid
     * @throws IllegalArgumentException if accessToken or subject is null or empty
     */
    UserInfo getUserInfo(String accessToken, String subject);

}
