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

import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for OpenID Connect UserInfo endpoint.
 * <p>
 * This controller handles UserInfo requests according to OpenID Connect Core 1.0 specification.
 * The endpoint returns claims about the authenticated End-User.
 * </p>
 * <p>
 * <b>Endpoint:</b> {@code GET /oauth2/userinfo}
 * </p>
 * <p>
 * <b>Authentication:</b> The client must authenticate using the access token obtained from
 * the token endpoint. This implementation uses session-based authentication for simplicity.
 * </p>
 * <p>
 * <b>Response Format:</b></p>
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 *
 * {
 *   "sub": "248289761001",
 *   "name": "Jane Doe",
 *   "email": "jane.doe@example.com",
 *   "preferred_username": "jane.doe"
 * }
 * </pre>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 - UserInfo</a>
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnExpression("'${open-agent-auth.roles.agent-user-idp.enabled:false}' == 'true' or '${open-agent-auth.roles.as-user-idp.enabled:false}' == 'true'")
public class OidcUserInfoController {

    /**
     * The logger for the UserInfo controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(OidcUserInfoController.class);

    /**
     * The user registry for fetching user information.
     */
    private final UserRegistry userRegistry;

    /**
     * Creates a new UserInfo controller.
     *
     * @param userRegistry the user registry for fetching user information
     */
    public OidcUserInfoController(UserRegistry userRegistry) {
        this.userRegistry = userRegistry;
    }

    /**
     * UserInfo endpoint.
     * <p>
     * Returns claims about the authenticated End-User according to OpenID Connect Core 1.0.
     * This implementation uses session-based authentication to retrieve the authenticated user.
     * </p>
     * <p>
     * <b>Standard Claims Returned:</b></p>
     * <ul>
     *   <li>sub - Subject identifier (REQUIRED)</li>
     *   <li>name - End-User's full name</li>
     *   <li>email - End-User's preferred email address</li>
     *   <li>preferred_username - End-User's preferred username</li>
     * </ul>
     *
     * @param session the HTTP session containing the authenticated user
     * @return the user info response
     */
    @GetMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.userinfo:/oauth2/userinfo}")
    public ResponseEntity<Map<String, Object>> userinfo(HttpSession session) {
        try {
            // Get authenticated user from session using SessionManager
            String subject = SessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER);
            if (subject == null) {
                logger.warn("UserInfo request failed: user not authenticated");
                return ResponseEntity
                        .status(HttpStatus.UNAUTHORIZED)
                        .body(createErrorResponse("invalid_token", "User not authenticated"));
            }

            // Extract username from subject (assuming subject is the username)
            String username = subject;

            // Fetch fresh user data from UserRegistry
            String name = userRegistry.getName(username);
            String email = userRegistry.getEmail(username);

            // Build UserInfo response
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("sub", subject);
            userInfo.put("name", name != null ? name : username);
            userInfo.put("email", email);
            userInfo.put("preferred_username", username);

            logger.info("UserInfo retrieved successfully for user: {}", username);

            return ResponseEntity.ok(userInfo);

        } catch (Exception e) {
            logger.error("Unexpected error processing UserInfo request: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Internal server error"));
        }
    }

    /**
     * Creates an error response map.
     *
     * @param error the error code
     * @param errorDescription the error description
     * @return the error response map
     */
    private Map<String, Object> createErrorResponse(String error, String errorDescription) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", error);
        response.put("error_description", errorDescription);
        return response;
    }
}