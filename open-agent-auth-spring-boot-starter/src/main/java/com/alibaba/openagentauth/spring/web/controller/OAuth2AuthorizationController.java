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

import com.alibaba.openagentauth.framework.web.authorization.AuthorizationOrchestrator;
import com.alibaba.openagentauth.framework.web.authorization.AuthorizationResult;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for OAuth 2.0 Authorization endpoint.
 * <p>
 * This controller serves as a facade for the authorization flow, delegating all
 * business logic to the {@link AuthorizationOrchestrator}. It follows the Facade
 * Pattern, providing a clean HTTP layer while keeping authorization logic separate.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Facade Pattern
 * </p>
 * <p>
 * <b>Responsibilities:</b></p>
 * <ul>
 *   <li>HTTP request/response handling</li>
 *   <li>Error handling and response formatting</li>
 *   <li>Delegation to AuthorizationOrchestrator for business logic</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Grant</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(AuthorizationOrchestrator.class)
public class OAuth2AuthorizationController {

    /**
     * The logger for the OAuth 2.0 authorization controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthorizationController.class);

    /**
     * The authorization orchestrator.
     */
    private final AuthorizationOrchestrator orchestrator;

    /**
     * Creates a new OAuth 2.0 authorization controller.
     *
     * @param orchestrator the authorization orchestrator (must not be null)
     */
    public OAuth2AuthorizationController(AuthorizationOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    /**
     * Authorization endpoint.
     * <p>
     * This endpoint handles authorization requests and delegates to the orchestrator
     * for processing. It supports both PAR (Pushed Authorization Request) and
     * traditional OAuth 2.0 authorization code flows.
     * </p>
     * <p>
     * <b>Request Parameters (PAR Flow):</b></p>
     * <ul>
     *   <li>{@code request_uri} - The URI of the pushed authorization request</li>
     *   <li>{@code state} - Optional state parameter for CSRF protection</li>
     * </ul>
     * <p>
     * <b>Request Parameters (Traditional Flow):</b></p>
     * <ul>
     *   <li>{@code response_type} - Must be "code"</li>
     *   <li>{@code client_id} - The OAuth 2.0 client identifier</li>
     *   <li>{@code redirect_uri} - The registered redirect URI</li>
     *   <li>{@code scope} - Optional requested scopes</li>
     *   <li>{@code state} - Optional state parameter for CSRF protection</li>
     * </ul>
     * <p>
     * <b>Request Parameters (Consent Submission):</b></p>
     * <ul>
     *   <li>{@code action} - The consent action ("consent", "approve", or "deny")</li>
     *   <li>Other parameters as per PAR or traditional flow</li>
     * </ul>
     *
     * @param request the HTTP request
     * @return redirect to callback, consent page, or error response
     */
    @GetMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.authorize:/oauth2/authorize}")
    public Object authorize(HttpServletRequest request) {
        // Process authorization request
        logger.info("Authorization request received: {}", request.getRequestURI());
        AuthorizationResult result = orchestrator.processAuthorization(request);
        return handleAuthorizationResult(result);
    }

    /**
     * Consent submission endpoint.
     * <p>
     * This endpoint handles consent form submissions and delegates to the
     * orchestrator for processing.
     * </p>
     *
     * @param request the HTTP request
     * @return redirect to callback or error response
     */
    @PostMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.authorize:/oauth2/authorize}")
    public Object handleConsentSubmission(HttpServletRequest request) {
        logger.info("Consent submission received: {}", request.getRequestURI());
        AuthorizationResult result = orchestrator.processConsentSubmission(request);
        return handleAuthorizationResult(result);
    }

    /**
     * Handles the authorization result and converts it to a Spring HTTP response.
     *
     * @param result the authorization result
     * @return Spring HTTP response (redirect, consent page, or error)
     */
    private Object handleAuthorizationResult(AuthorizationResult result) {
        return switch (result.getType()) {
            case REDIRECT -> new RedirectView(result.getRedirectUri());
            case ERROR -> {
                Map<String, String> errorBody = new HashMap<>();
                errorBody.put("error", result.getError());
                if (result.getErrorDescription() != null) {
                    errorBody.put("error_description", result.getErrorDescription());
                }
                yield ResponseEntity.status(result.getHttpStatus()).body(errorBody);
            }
            case CONSENT_PAGE -> result.getConsentPage();
        };
    }
}