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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Strategy interface for authorization flow processing.
 * <p>
 * This interface defines the contract for different OAuth 2.0 authorization flow strategies.
 * It follows the Strategy Pattern, allowing different flow implementations (PAR, Traditional, etc.)
 * to be plugged in without modifying the orchestration logic.
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Open/Closed Principle:</b> New flow types can be added by implementing this interface
 *       without modifying existing code</li>
 *   <li><b>Single Responsibility Principle:</b> Each strategy handles only one specific flow type</li>
 *   <li><b>Interface Segregation Principle:</b> The interface contains only methods necessary
 *       for authorization flow processing</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0 Authorization Framework</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public interface AuthorizationFlowStrategy {

    /**
     * Determines if this strategy supports the given authorization request.
     *
     * @param request the HTTP request
     * @return true if this strategy can handle the request, false otherwise
     */
    boolean supports(HttpServletRequest request);

    /**
     * Parses the authorization request from the HTTP request.
     *
     * @param request the HTTP request
     * @return the authorization request context
     * @throws OAuth2AuthorizationException if parsing fails
     */
    AuthorizationRequestContext parseRequest(HttpServletRequest request);

    /**
     * Validates the authorization request.
     *
     * @param context the authorization request context
     * @throws OAuth2AuthorizationException if validation fails
     */
    void validateRequest(AuthorizationRequestContext context);

    /**
     * Issues an authorization code for the given context and user.
     *
     * @param context the authorization request context
     * @param subject the authenticated user subject
     * @return the authorization code result
     * @throws OAuth2AuthorizationException if authorization fails
     */
    AuthorizationCodeResult issueCode(AuthorizationRequestContext context, String subject);

    /**
     * Builds the redirect URI with authorization code.
     * <p>
     * This method constructs the final redirect URI that includes the authorization code
     * and optional state parameter. It follows the OAuth 2.0 specification for authorization
     * response (RFC 6749 Section 4.1.2).
     * </p>
     *
     * @param result the authorization code result containing code and redirect information
     * @return the complete redirect URI with authorization code
     */
    default String buildRedirectUri(AuthorizationCodeResult result) {
        return AuthorizationUriBuilder.buildRedirectUri(result);
    }
}
