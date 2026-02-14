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
package com.alibaba.openagentauth.framework.web.provider;

import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Provider for rendering and handling the user consent page in OAuth 2.0 authorization flow.
 * <p>
 * This interface defines the contract for displaying the authorization consent
 * page to users and handling their consent decisions. Implementations can provide
 * custom consent page designs, branding, and consent workflows.
 * </p>
 * <p>
 * <b>Usage:</b></p>
 * <pre>
 * // Render consent page
 * Object consentPage = consentPageProvider.renderConsentPage(
 *     request, 
 *     requestUri, 
 *     subject, 
 *     clientId, 
 *     scopes
 * );
 * </pre>
 * <p>
 * <b>Agent Operation Authorization Support:</b></p>
 * <p>
 * For PAR flows with Agent Operation Authorization, the provider receives
 * a ParJwtClaims object containing:
 * </p>
 * <ul>
 *   <li>{@code evidence} - User's original input as JWT-VC</li>
 *   <li>{@code agentUserBindingProposal} - Agent-user binding proposal</li>
 *   <li>{@code operationProposal} - Rego policy string</li>
 *   <li>{@code context} - Operation request context</li>
 * </ul>
 * <p>
 * <b>Extension Points:</b></p>
 * <ul>
 *   <li>Custom consent page UI and branding</li>
 *   <li>Detailed scope descriptions</li>
 *   <li>Progressive consent workflows</li>
 *   <li>Consent history display</li>
 *   <li>Multi-step consent flows</li>
 * </ul>
 *
 * @since 1.0
 */
public interface ConsentPageProvider {

    /**
     * Renders the authorization consent page.
     * <p>
     * This method should return an object that represents the consent page.
     * The page should display the authorization request details including
     * the client name, requested scopes, and allow the user to approve or deny.
     * </p>
     * <p>
     * <b>Note:</b> The return type is {@code Object} to avoid Spring dependencies.
     * In a Spring Boot application, this can be a {@code ModelAndView},
     * {@code String} (view name), or any other type that Spring MVC can handle.
     * </p>
     *
     * @param request the HTTP request
     * @param requestUri the PAR request URI containing authorization parameters
     * @param subject the authenticated user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param scopes the requested scopes
     * @return the object representing the consent page
     */
    Object renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes
    );

    /**
     * Renders the authorization consent page with Agent Operation Authorization claims.
     * <p>
     * This method is called for PAR flows that contain Agent Operation Authorization
     * information. The page should display detailed information about the proposed
     * operation, including the user's original input, agent proposal, and operation context.
     * </p>
     *
     * @param request the HTTP request
     * @param requestUri the PAR request URI containing authorization parameters
     * @param subject the authenticated user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param scopes the requested scopes
     * @param parClaims the PAR JWT claims containing Agent Operation Authorization information
     * @return the object representing the consent page
     */
    default Object renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes,
            ParJwtClaims parClaims
    ) {
        // Default implementation: fall back to basic consent page
        return renderConsentPage(request, requestUri, subject, clientId, scopes);
    }

    /**
     * Handles the user's consent response.
     * <p>
     * This method should process the user's consent decision from the consent page
     * form submission. It should return true if the user approved the request,
     * false if denied.
     * </p>
     *
     * @param request the HTTP request containing the consent form submission
     * @return true if the user approved, false if denied
     */
    boolean handleConsentResponse(HttpServletRequest request);

    /**
     * Checks if consent is required for this authorization request.
     * <p>
     * This method can be used to skip consent for previously approved requests
     * or for trusted clients. If this method returns false, the authorization
     * flow will proceed directly without showing the consent page.
     * </p>
     *
     * @param request the HTTP request
     * @param subject the authenticated user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param scopes the requested scopes
     * @return true if consent is required, false otherwise
     */
    default boolean isConsentRequired(
            HttpServletRequest request,
            String subject,
            String clientId,
            String scopes
    ) {
        return true;
    }

    /**
     * Renders the authorization consent page for traditional OAuth 2.0 flow.
     * <p>
     * This method should return an object that represents the consent page
     * for traditional OAuth 2.0 authorization code flow (without PAR).
     * The page should display the authorization request details including
     * the client name, requested scopes, and allow the user to approve or deny.
     * </p>
     *
     * @param request the HTTP request
     * @param subject the authenticated user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param redirectUri the redirect URI
     * @param state the state parameter for CSRF protection
     * @param scopes the requested scopes
     * @return the object representing the consent page
     */
    default Object renderConsentPageTraditional(
            HttpServletRequest request,
            String subject,
            String clientId,
            String redirectUri,
            String state,
            String scopes
    ) {
        // Default implementation: reuse the PAR consent page with null requestUri
        return renderConsentPage(request, null, subject, clientId, scopes);
    }
}
