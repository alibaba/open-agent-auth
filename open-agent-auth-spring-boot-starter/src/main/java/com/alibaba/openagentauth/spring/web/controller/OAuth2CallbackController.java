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

import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackRequest;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackResult;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * OAuth2 Callback Controller
 * <p>
 * Handles OAuth2 callback requests from the authorization server.
 * This controller delegates the business logic to CallbackService.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Controller Pattern + Delegation Pattern</p>
 * <p>
 * <b>Responsibilities:</b></p>
 * <ul>
 *   <li>Receive OAuth2 callback requests</li>
 *   <li>Delegate business logic to CallbackService</li>
 *   <li>Convert CallbackResult to Spring ResponseEntity</li>
 * </ul>
 *
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(OAuth2CallbackService.class)
public class OAuth2CallbackController {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2CallbackController.class);
    
    private final OAuth2CallbackService callbackService;
    private final OpenAgentAuthProperties properties;
    
    public OAuth2CallbackController(
            OAuth2CallbackService callbackService,
            OpenAgentAuthProperties properties) {
        this.callbackService = callbackService;
        this.properties = properties;
    }

    /**
     * Handles OAuth2 callback from the authorization server.
     * <p>
     * This method is called when the authorization server redirects back to the
     * application after user authorization. It delegates the business logic to
     * CallbackService.
     * </p>
     *
     * @param code           the authorization code received from the authorization server
     * @param state          the state parameter for CSRF protection and flow identification
     * @param error          the error code (if authorization failed)
     * @param errorDescription the error description (if authorization failed)
     * @param request        the HTTP request
     * @return redirect to home page or error response
     */
    @GetMapping("${open-agent-auth.capabilities.oauth2-client.endpoints.callback:/callback}")
    public Object callback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription,
            HttpServletRequest request) {

        logger.info("Received OAuth callback: code={}, state={}, error={}", 
                    code != null ? code.substring(0, Math.min(10, code.length())) + "..." : "null",
                    state, error);

        // Create OAuth2CallbackRequest with HttpServletRequest directly
        OAuth2CallbackRequest callbackRequest = new OAuth2CallbackRequest(code, state, error, errorDescription, request);

        // Get client ID from configuration
        String clientId = properties.getCapabilities().getOAuth2Client().getCallback().getClientId();
        if (clientId == null || clientId.isBlank()) {
            logger.error("OAuth client ID is not configured. Please set 'open-agent-auth.server.callback.client-id' in your configuration.");
            return ResponseEntity.internalServerError()
                    .body(Map.of(
                        "error", "server_error",
                        "error_description", "Client ID not configured"
                    ));
        }

        // Delegate to OAuth2CallbackService
        OAuth2CallbackResult result = callbackService.handleCallback(callbackRequest, clientId);

        // Convert OAuth2CallbackResult to Spring ResponseEntity
        return convertCallbackResult(result);
    }

    /**
     * Converts OAuth2CallbackResult to Spring ResponseEntity.
     *
     * @param result the OAuth2CallbackResult from OAuth2CallbackService
     * @return Spring ResponseEntity
     */
    private Object convertCallbackResult(OAuth2CallbackResult result) {
        if (result.isSuccess()) {
            logger.info("Callback processing successful, redirecting to: {}", result.getRedirectUrl());
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header("Location", result.getRedirectUrl())
                    .build();
        } else {
            logger.error("Callback processing failed: {}", result.getErrorResponse());
            return ResponseEntity.status(result.getStatusCode())
                    .body(result.getErrorResponse());
        }
    }
}