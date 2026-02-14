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
package com.alibaba.openagentauth.core.model.oauth2.par;

import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.Objects;

/**
 * Represents a Pushed Authorization Response according to RFC 9126.
 * <p>
 * This class encapsulates the response returned by the Authorization Server's
 * PAR endpoint after successfully processing a pushed authorization request.
 * </p>
 * <p>
 * <b>Response Format (RFC 9126 Section 2.2):</b></p>
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 *
 * {
 *   "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
 *   "expires_in": 90
 * }
 * </pre>
 * <p>
 * <b>Fields:</b></p>
 * <ul>
 *   <li><b>request_uri:</b> REQUIRED - The URI reference to the authorization request</li>
 *   <li><b>expires_in:</b> REQUIRED - The lifetime of the request_uri in seconds</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class ParResponse {

    /**
     * The request URI returned by the Authorization Server.
     * <p>
     * This is a URN reference to the authorization request that was pushed.
     * Format: urn:ietf:params:oauth:request_uri:{random_value}
     * </p>
     */
    private final String requestUri;

    /**
     * The lifetime of the request_uri in seconds.
     * <p>
     * After this time, the request_uri will expire and cannot be used.
     * </p>
     */
    private final int expiresIn;

    private ParResponse(String requestUri, int expiresIn) {
        this.requestUri = requestUri;
        this.expiresIn = expiresIn;
    }

    /**
     * Gets the request URI.
     *
     * @return the request URI
     */
    public String getRequestUri() {
        return requestUri;
    }

    /**
     * Gets the expiration time in seconds.
     *
     * @return the expiration time in seconds
     */
    public int getExpiresIn() {
        return expiresIn;
    }

    /**
     * Creates a successful PAR response.
     *
     * @param requestUri the request URI
     * @param expiresIn the expiration time in seconds
     * @return a successful PAR response
     * @throws IllegalArgumentException if requestUri is null or blank, or expiresIn is negative
     */
    public static ParResponse success(String requestUri, int expiresIn) {
        ValidationUtils.validateNotNull(requestUri, "request_uri");
        if (requestUri.trim().isEmpty()) {
            throw new IllegalArgumentException("request_uri cannot be blank");
        }
        if (expiresIn < 0) {
            throw new IllegalArgumentException("expires_in cannot be negative");
        }
        return new ParResponse(requestUri, expiresIn);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParResponse that = (ParResponse) o;
        return expiresIn == that.expiresIn && Objects.equals(requestUri, that.requestUri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(requestUri, expiresIn);
    }

    @Override
    public String toString() {
        return "ParResponse{" +
                "requestUri='" + requestUri + '\'' +
                ", expiresIn=" + expiresIn +
                '}';
    }
}