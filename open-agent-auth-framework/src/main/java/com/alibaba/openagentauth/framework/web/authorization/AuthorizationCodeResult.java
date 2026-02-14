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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import java.util.Objects;

/**
 * Authorization code result.
 * <p>
 * This is an immutable value object that represents the result of an authorization code issuance.
 * It follows the Effective Java principle of immutability for thread safety.
 * </p>
 *
 * @since 1.0
 */
public final class AuthorizationCodeResult {

    private final String code;
    private final String redirectUri;
    private final String state;

    /**
     * Creates a new authorization code result.
     *
     * @param code the authorization code (must not be null)
     * @param redirectUri the redirect URI (must not be null)
     * @param state the state parameter (can be null)
     * @throws IllegalArgumentException if code or redirectUri is null
     */
    public AuthorizationCodeResult(String code, String redirectUri, String state) {
        this.code = ValidationUtils.validateNotNull(code, "code");
        this.redirectUri = ValidationUtils.validateNotNull(redirectUri, "redirectUri");
        this.state = state;
    }

    /**
     * Gets the authorization code.
     *
     * @return the authorization code
     */
    public String getCode() {
        return code;
    }

    /**
     * Gets the redirect URI.
     *
     * @return the redirect URI
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Gets the state parameter.
     *
     * @return the state parameter, or null if not provided
     */
    public String getState() {
        return state;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationCodeResult that = (AuthorizationCodeResult) o;
        return Objects.equals(code, that.code)
                && Objects.equals(redirectUri, that.redirectUri)
                && Objects.equals(state, that.state);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code, redirectUri, state);
    }

    @Override
    public String toString() {
        return "AuthorizationCodeResult{" +
                "code='" + code + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", state='" + state + '\'' +
                '}';
    }
}
