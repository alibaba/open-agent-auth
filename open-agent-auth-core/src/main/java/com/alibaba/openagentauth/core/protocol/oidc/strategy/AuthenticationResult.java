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
package com.alibaba.openagentauth.core.protocol.oidc.strategy;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import java.util.Arrays;
import java.util.Objects;

/**
 * Represents the result of a user authentication attempt.
 * <p>
 * This class encapsulates the outcome of an authentication operation,
 * including the authenticated subject identifier and the authentication
 * methods used.
 * </p>
 * <p>
 * <b>Authentication Methods References (amr):</b></p>
 * According to OpenID Connect Core 1.0, the amr claim contains an array
 * of strings that identify the authentication methods used. Common values include:
 * <ul>
 *   <li>pwd - Password-based authentication</li>
 *   <li>mfa - Multi-factor authentication</li>
 *   <li>sms - SMS-based authentication</li>
 *   <li>otp - One-time password</li>
 *   <li>geo - Geolocation verification</li>
 *   <li>hwk - Hardware key authentication</li>
 *   <li>swk - Software key authentication</li>
 *   <li>tel - Telephone callback</li>
 *   <li>geo - Geolocation verification</li>
 *   <li>none - No authentication (for login_hint)</li>
 *   <li>id_token - ID token-based authentication</li>
 * </ul>
 *
 * @since 1.0
 */
public class AuthenticationResult {

    private final String subject;
    private final String[] authenticationMethods;

    /**
     * Creates a new AuthenticationResult.
     *
     * @param subject the authenticated subject identifier
     * @param authenticationMethods array of authentication method references (amr)
     */
    public AuthenticationResult(String subject, String[] authenticationMethods) {
        this.subject = ValidationUtils.validateNotNull(subject, "Subject");
        this.authenticationMethods = ValidationUtils.validateNotNull(authenticationMethods, "Authentication methods");
    }

    /**
     * Gets the subject identifier.
     *
     * @return the subject identifier
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Gets the authentication methods references.
     *
     * @return array of authentication method identifiers
     */
    public String[] getAuthenticationMethods() {
        return authenticationMethods;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationResult that = (AuthenticationResult) o;
        return Objects.equals(subject, that.subject) && 
               Arrays.equals(authenticationMethods, that.authenticationMethods);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(subject);
        result = 31 * result + Arrays.hashCode(authenticationMethods);
        return result;
    }

    @Override
    public String toString() {
        return "AuthenticationResult{" +
                "subject='" + subject + '\'' +
                ", authenticationMethods=" + Arrays.toString(authenticationMethods) +
                '}';
    }
}