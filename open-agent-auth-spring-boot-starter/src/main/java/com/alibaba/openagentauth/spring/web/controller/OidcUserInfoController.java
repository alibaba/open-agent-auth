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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.verify.SignatureVerificationUtils;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.KEY_ID_TOKEN_SIGNING;

/**
 * Controller for OpenID Connect UserInfo endpoint.
 * <p>
 * This controller handles UserInfo requests according to OpenID Connect Core 1.0 Section 5.3.
 * The endpoint returns claims about the authenticated End-User. Clients MUST authenticate
 * using a Bearer Token (access token) obtained from the token endpoint, sent via the
 * {@code Authorization} header per RFC 6750.
 * </p>
 * <p>
 * <b>Endpoint:</b> {@code GET /oauth2/userinfo}
 * </p>
 * <p>
 * <b>Authentication:</b> Bearer Token via {@code Authorization: Bearer <access_token>} header.
 * The access token is a signed JWT (ID Token) whose signature is verified using the
 * configured signing key.
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
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6750">RFC 6750 - Bearer Token Usage</a>
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(UserRegistry.class)
public class OidcUserInfoController {

    private static final Logger logger = LoggerFactory.getLogger(OidcUserInfoController.class);

    /**
     * The Bearer token prefix in the Authorization header.
     */
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Internal record to hold access token information extracted from JWT.
     * Contains the subject identifier and the scope claim.
     */
    private record AccessTokenInfo(String subject, String scope) {
    }

    /**
     * The user registry for fetching user information.
     */
    private final UserRegistry userRegistry;

    /**
     * The key manager for resolving JWT verification keys.
     */
    private final KeyManager keyManager;

    /**
     * The verification key ID used for access token signature verification.
     */
    private final String verificationKeyId;

    /**
     * Creates a new UserInfo controller with Bearer Token authentication support.
     *
     * @param userRegistry the user registry for fetching user information
     * @param keyManager the key manager for resolving JWT verification keys
     * @param openAgentAuthProperties the configuration properties for key resolution
     */
    public OidcUserInfoController(UserRegistry userRegistry,
                                  KeyManager keyManager,
                                  OpenAgentAuthProperties openAgentAuthProperties) {
        this.userRegistry = userRegistry;
        this.keyManager = keyManager;
        this.verificationKeyId = resolveVerificationKeyId(openAgentAuthProperties);
        logger.info("OidcUserInfoController initialized with Bearer Token authentication, verificationKeyId: {}",
                verificationKeyId);
    }

    /**
     * UserInfo endpoint (OIDC Core 1.0 Section 5.3).
     * <p>
     * Returns claims about the authenticated End-User. The client MUST present a valid
     * Bearer Token in the {@code Authorization} header. The token is verified as a signed
     * JWT, and the subject ({@code sub}) claim is used to look up user information.
     * </p>
     *
     * @param request the HTTP request containing the Authorization header
     * @return the user info response
     */
    @GetMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.userinfo:/oauth2/userinfo}")
    public ResponseEntity<Map<String, Object>> userinfo(HttpServletRequest request) {
        try {
            // Step 1: Extract Bearer Token from Authorization header (RFC 6750 Section 2.1)
            String accessToken = extractBearerToken(request);
            if (accessToken == null) {
                logger.warn("UserInfo request failed: missing or malformed Authorization header");
                return unauthorizedResponse("invalid_request", "Missing or malformed Authorization header");
            }

            // Step 2: Parse and verify the access token (signed JWT) and extract subject and scope
            AccessTokenInfo tokenInfo = verifyAccessTokenAndExtractInfo(accessToken);
            if (tokenInfo == null || tokenInfo.subject() == null) {
                logger.warn("UserInfo request failed: invalid access token");
                return unauthorizedResponse("invalid_token", "Access token is invalid or expired");
            }

            // Step 3: Build UserInfo response with claims filtered by scope (OIDC Core 1.0 Section 5.4)
            Map<String, Object> userInfo = buildUserInfoResponse(tokenInfo.subject(), tokenInfo.scope());

            logger.info("UserInfo retrieved successfully for user: {}", tokenInfo.subject());
            return ResponseEntity.ok(userInfo);

        } catch (Exception e) {
            logger.error("Unexpected error processing UserInfo request: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Internal server error"));
        }
    }

    /**
     * Extracts the Bearer Token from the Authorization header per RFC 6750 Section 2.1.
     *
     * @param request the HTTP request
     * @return the access token string, or null if not present or malformed
     */
    private String extractBearerToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = authorizationHeader.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    /**
     * Verifies the access token signature and extracts the subject and scope claims.
     * <p>
     * The access token is expected to be a signed JWT (ID Token). This method:
     * <ol>
     *   <li>Parses the JWT</li>
     *   <li>Resolves the verification key from {@link KeyManager}</li>
     *   <li>Verifies the JWT signature</li>
     *   <li>Validates the token has not expired</li>
     *   <li>Extracts and returns the {@code sub} and {@code scope} claims</li>
     * </ol>
     * </p>
     *
     * @param accessToken the access token string
     * @return the AccessTokenInfo containing subject and scope, or null if verification fails
     */
    private AccessTokenInfo verifyAccessTokenAndExtractInfo(String accessToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(accessToken);

            // Verify signature using KeyManager
            JWK verificationKey = keyManager.resolveVerificationKey(verificationKeyId);
            JWSVerifier verifier = SignatureVerificationUtils.createVerifier(verificationKey);

            if (!signedJWT.verify(verifier)) {
                logger.warn("Access token signature verification failed");
                return null;
            }

            // Validate expiration
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && expirationTime.before(new Date())) {
                logger.warn("Access token has expired at: {}", expirationTime);
                return null;
            }

            // Extract subject
            String subject = claimsSet.getSubject();
            if (subject == null || subject.isBlank()) {
                logger.warn("Access token missing subject claim");
                return null;
            }

            // Extract scope claim (space-separated string)
            String scope = null;
            Object scopeClaim = claimsSet.getClaim("scope");
            if (scopeClaim != null) {
                scope = scopeClaim.toString();
            }

            logger.debug("Access token verified successfully for subject: {}, scope: {}", subject, scope);
            return new AccessTokenInfo(subject, scope);

        } catch (Exception e) {
            logger.warn("Failed to verify access token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Builds the UserInfo response with claims filtered by scope according to OIDC Core 1.0 Section 5.4.
     * <p>
     * The scope claim is a space-separated string of scope values. Claims are returned based on the
     * requested scopes:
     * </p>
     * <ul>
     *   <li>{@code openid} scope: always includes {@code sub} (required per OIDC Core 1.0 Section 5.3.2)</li>
     *   <li>{@code profile} scope: includes {@code name} and {@code preferred_username}</li>
     *   <li>{@code email} scope: includes {@code email}</li>
     * </ul>
     * <p>
     * If no scope claim is present or scope is empty, all claims are returned for backward compatibility.
     * </p>
     *
     * @param subject the subject identifier
     * @param scope the space-separated scope string from the access token, or null/empty
     * @return the filtered user info claims map
     */
    private Map<String, Object> buildUserInfoResponse(String subject, String scope) {
        Map<String, Object> userInfo = new HashMap<>();

        // Parse scope into set for easy lookup
        Set<String> scopes = new HashSet<>();
        if (scope != null && !scope.isBlank()) {
            scopes.addAll(Arrays.asList(scope.split("\\s+")));
        }

        // Backward compatibility: if no scope claim, return all claims
        boolean returnAllClaims = scopes.isEmpty();

        // sub is always included per OIDC Core 1.0 Section 5.3.2
        userInfo.put("sub", subject);

        // Fetch user data from UserRegistry
        String name = userRegistry.getName(subject);
        String email = userRegistry.getEmail(subject);

        // Add profile claims if profile scope is requested or returning all claims
        if (returnAllClaims || scopes.contains("profile")) {
            userInfo.put("name", name != null ? name : subject);
            userInfo.put("preferred_username", subject);
        }

        // Add email claim if email scope is requested or returning all claims
        if (returnAllClaims || scopes.contains("email")) {
            userInfo.put("email", email);
        }

        return userInfo;
    }

    /**
     * Resolves the verification key ID from configuration.
     * <p>
     * The key ID is resolved from the {@code id-token-signing} key definition.
     * This is the same key used by {@link com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator}
     * to sign ID Tokens, ensuring signature verification consistency.
     * </p>
     *
     * @param properties the configuration properties
     * @return the verification key ID
     */
    private static String resolveVerificationKeyId(OpenAgentAuthProperties properties) {
        var keyConfig = properties.getKeyDefinition(KEY_ID_TOKEN_SIGNING);
        if (keyConfig != null && keyConfig.getKeyId() != null) {
            return keyConfig.getKeyId();
        }
        logger.warn("ID token signing key not configured, using default key ID: id-token-signing-key");
        return "id-token-signing-key";
    }

    /**
     * Creates a 401 Unauthorized response with WWW-Authenticate header per RFC 6750 Section 3.
     *
     * @param error the error code
     * @param errorDescription the error description
     * @return the unauthorized response entity
     */
    private ResponseEntity<Map<String, Object>> unauthorizedResponse(String error, String errorDescription) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .header("WWW-Authenticate",
                        "Bearer error=\"" + error + "\", error_description=\"" + errorDescription + "\"")
                .body(createErrorResponse(error, errorDescription));
    }

    /**
     * Creates an error response map per OIDC Core 1.0 Section 5.3.3.
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