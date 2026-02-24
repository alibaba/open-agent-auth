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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtParser;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Controller for handling OAuth 2.0 consent page.
 * <p>
 * This controller integrates with the framework's ConsentPageProvider to
 * display and process the user consent page. It provides a custom implementation
 * that can be extended with additional business logic.
 * </p>
 *
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(ConsentPageProvider.class)
public class OAuth2ConsentController {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2ConsentController.class);

    private final UserAuthenticationInterceptor userAuthenticationInterceptor;
    private final ConsentPageProvider consentPageProvider;
    @Nullable
    private final OAuth2ParServer parServer;
    private final AapParJwtParser parJwtParser;

    @Autowired
    public OAuth2ConsentController(
            UserAuthenticationInterceptor userAuthenticationInterceptor,
            ConsentPageProvider consentPageProvider,
            @Autowired(required = false) @Nullable OAuth2ParServer parServer) {
        this.userAuthenticationInterceptor = userAuthenticationInterceptor;
        this.consentPageProvider = consentPageProvider;
        this.parServer = parServer;
        this.parJwtParser = new AapParJwtParser();
    }

    /**
     * Displays the consent page.
     * <p>
     * This endpoint is called by the framework's OAuth2AuthorizationController
     * when user consent is required. It delegates to the ConsentPageProvider
     * to render the consent page.
     * </p>
     *
     * @param request the HTTP request
     * @param requestUri the PAR request URI
     * @return the consent page view
     */
    @GetMapping("/oauth2/consent")
    public ModelAndView consentPage(HttpServletRequest request, @RequestParam String requestUri) {
        logger.info("Displaying consent page for request_uri: {}", requestUri);

        // Authenticate user
        String subject = userAuthenticationInterceptor.authenticate(request);
        if (subject == null) {
            logger.warn("User not authenticated, redirecting to login");
            return new ModelAndView(new RedirectView("/login?redirect_uri=" +
                    request.getRequestURI() + "?requestUri=" + requestUri));
        }

        // Extract PAR JWT claims, client ID and scope for display
        ParJwtClaims parJwtClaims = null;
        ParRequest parRequest = null;
        if (parServer != null) {
            try {
                parRequest = parServer.retrieveRequest(requestUri);
                if (parRequest != null && parRequest.getRequestJwt() != null && !parRequest.getRequestJwt().isBlank()) {
                    parJwtClaims = parJwtParser.parse(parRequest.getRequestJwt());
                    if (parJwtClaims != null) {
                        logger.info("Successfully extracted PAR JWT claims for display with JTI: {}", parJwtClaims.getJwtId());
                    }
                }
            } catch (Exception e) {
                logger.error("Error extracting PAR JWT claims for display", e);
            }
        } else {
            logger.debug("PAR server not available, skipping PAR JWT claims extraction");
        }

        // Use framework's consent page provider with PAR claims if available
        String clientId = parRequest != null ? parRequest.getClientId() : null;
        String scope = parRequest != null ? parRequest.getScope() : null;
        Object result = null;
        if (parJwtClaims != null) {
            logger.info("Rendering consent page with PAR claims");
            result = consentPageProvider.renderConsentPage(request, requestUri, subject, clientId, scope, parJwtClaims);

        } else {
            logger.info("Rendering consent page without PAR claims");
            result = consentPageProvider.renderConsentPage(request, requestUri, subject, clientId, scope);
        }
        if (result instanceof ModelAndView) {
            return (ModelAndView)result;
        }
        // Fallback: create a default ModelAndView if result is not ModelAndView
        return new ModelAndView("consent");
    }

    /**
     * Handles consent form submission.
     * <p>
     * This endpoint processes the user's consent decision and redirects back
     * to the authorization endpoint with the appropriate action.
     * </p>
     *
     * @param requestUri the PAR request URI
     * @param action the user's action (approve or deny)
     * @return redirect to authorization endpoint
     */
    @PostMapping("/oauth2/consent")
    public RedirectView handleConsent(@RequestParam String requestUri, @RequestParam String action) {
        logger.info("Processing consent submission: {} for request_uri: {}", action, requestUri);

        // Pass the actual user action (approve or deny) to the authorization endpoint
        return new RedirectView("/oauth2/authorize?request_uri=" + requestUri + "&action=" + action);
    }
}
