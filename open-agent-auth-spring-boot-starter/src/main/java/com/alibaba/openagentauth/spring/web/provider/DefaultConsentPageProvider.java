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
package com.alibaba.openagentauth.spring.web.provider;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.ModelAndView;

/**
 * Default implementation of {@link ConsentPageProvider}.
 * <p>
 * This implementation provides a simple consent page template that displays
 * the authorization request details and allows users to approve or deny.
 * It uses a default Thymeleaf template located at {@code consent}.
 * </p>
 * <p>
 * <b>Template Model:</b></p>
 * <ul>
 *   <li>{@code requestUri} - The PAR request URI</li>
 *   <li>{@code subject} - The authenticated user subject</li>
 *   <li>{@code clientId} - The OAuth 2.0 client identifier</li>
 *   <li>{@code scopes} - The requested scopes</li>
 *   <li>{@code parClaims} - The PAR JWT claims (for Agent Operation Authorization)</li>
 *   <li>{@code evidence} - The user's original input as JWT-VC</li>
 *   <li>{@code operationProposal} - The Rego policy string</li>
 *   <li>{@code context} - The operation request context</li>
 * </ul>
 * <p>
 * <b>Form Submission:</b></p>
 * The consent page should submit a form with:
 * <ul>
 *   <li>{@code request_uri} - The PAR request URI</li>
 *   <li>{@code action} - Either "approve" or "deny"</li>
 * </ul>
 *
 * @see ConsentPageProvider
 * @since 1.0
 */
public class DefaultConsentPageProvider implements ConsentPageProvider {

    /**
     * The logger for consent page provider.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultConsentPageProvider.class);

    /**
     * Default view name for the consent page.
     */
    public static final String DEFAULT_VIEW_NAME = "consent";

    /**
     * The Thymeleaf template view name.
     */
    private final String viewName;

    /**
     * The display name for the IDP (e.g., "AS User IDP", "Agent User IDP").
     */
    private final String displayName;

    /**
     * Creates a new DefaultConsentPageProvider with default view name.
     */
    public DefaultConsentPageProvider() {
        this(DEFAULT_VIEW_NAME, "Identity Provider");
    }

    /**
     * Creates a new DefaultConsentPageProvider with custom view name.
     *
     * @param viewName the Thymeleaf template view name
     */
    public DefaultConsentPageProvider(String viewName) {
        this(viewName, "Identity Provider");
    }

    /**
     * Creates a new DefaultConsentPageProvider with custom view name and display name.
     *
     * @param viewName the Thymeleaf template view name
     * @param displayName the display name for the IDP
     */
    public DefaultConsentPageProvider(String viewName, String displayName) {
        this.viewName = viewName;
        this.displayName = displayName;
    }

    @Override
    public ModelAndView renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes
    ) {
        logger.info("Rendering consent page for user: {}, client: {}", subject, clientId);

        ModelAndView mv = new ModelAndView(viewName);
        mv.addObject("requestUri", requestUri);
        mv.addObject("subject", subject);
        mv.addObject("clientId", clientId);
        mv.addObject("scopes", scopes);
        mv.addObject("displayName", displayName);

        return mv;
    }

    @Override
    public ModelAndView renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes,
            ParJwtClaims parClaims
    ) {
        logger.info("Rendering consent page with PAR claims for user: {}, client: {}", subject, clientId);

        ModelAndView mv = new ModelAndView(viewName);
        mv.addObject("requestUri", requestUri);
        mv.addObject("subject", subject);
        mv.addObject("clientId", clientId);
        mv.addObject("scopes", scopes);
        mv.addObject("displayName", displayName);

        // Add Agent Operation Authorization specific information
        if (parClaims != null) {
            mv.addObject("parClaims", parClaims);
            
            // Extract individual components for easier template access
            Evidence evidence = parClaims.getEvidence();
            if (evidence != null) {
                mv.addObject("evidence", evidence);
                mv.addObject("sourcePromptCredential", evidence.getSourcePromptCredential());
            }

            String operationProposal = parClaims.getOperationProposal();
            if (operationProposal != null) {
                mv.addObject("operationProposal", operationProposal);
            }

            OperationRequestContext context = parClaims.getContext();
            if (context != null) {
                mv.addObject("context", context);
            }

            AgentUserBindingProposal bindingProposal = parClaims.getAgentUserBindingProposal();
            if (bindingProposal != null) {
                mv.addObject("agentUserBindingProposal", bindingProposal);
            }

            logger.info("Added PAR claims to model: evidence={}, operationProposal={}, context={}", 
                    evidence != null, operationProposal != null, context != null);
        }

        return mv;
    }

    @Override
    public boolean handleConsentResponse(HttpServletRequest request) {
        String action = request.getParameter("action");
        boolean approved = "approve".equalsIgnoreCase(action);

        logger.info("User consent action: {}, approved: {}", action, approved);
        return approved;
    }

    @Override
    public boolean isConsentRequired(
            HttpServletRequest request,
            String subject,
            String clientId,
            String scopes
    ) {
        // Default implementation always requires consent
        // Implementations can override to skip consent for previously approved requests
        return true;
    }

    @Override
    public ModelAndView renderConsentPageTraditional(
            HttpServletRequest request,
            String subject,
            String clientId,
            String redirectUri,
            String state,
            String scopes
    ) {
        logger.info("Rendering traditional consent page for user: {}, client: {}", subject, clientId);

        ModelAndView mv = new ModelAndView(viewName);
        mv.addObject("requestUri", null); // Traditional flow doesn't use request_uri
        mv.addObject("subject", subject);
        mv.addObject("clientId", clientId);
        mv.addObject("redirectUri", redirectUri);
        mv.addObject("state", state);
        mv.addObject("scopes", scopes);
        mv.addObject("displayName", displayName);

        return mv;
    }
}