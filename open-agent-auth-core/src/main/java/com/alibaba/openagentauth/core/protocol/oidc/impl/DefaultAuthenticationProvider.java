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
package com.alibaba.openagentauth.core.protocol.oidc.impl;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.exception.oidc.OidcRfcErrorCode;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.strategy.AuthenticationMethod;
import com.alibaba.openagentauth.core.protocol.oidc.strategy.AuthenticationResult;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of {@link AuthenticationProvider}.
 * <p>
 * This implementation uses a pluggable {@link UserRegistry} for user authentication,
 * allowing different storage backends to be used through custom implementations.
 * It validates authentication requests, authenticates users through the registry,
 * and issues ID Tokens.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Pluggable user registry for flexible authentication backends</li>
 *   <li>Request validation</li>
 *   <li>User authentication via registry</li>
 *   <li>Session management</li>
 *   <li>ID Token generation</li>
 *   <li>Nonce validation</li>
 * </ul>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * // Create an in-memory user registry
 * UserRegistry registry = new InMemoryUserRegistry();
 * 
 * // Add users explicitly
 * registry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
 *
 * // Create authentication provider
 * AuthenticationProvider provider = new DefaultAuthenticationProvider(
 *     idTokenGenerator,
 *     registry,
 *     null  // maxAge
 * );
 * }</pre>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">OpenID Connect Core 1.0 - Authentication</a>
 * @since 1.0
 */
public class DefaultAuthenticationProvider implements AuthenticationProvider {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultAuthenticationProvider.class);

    /**
     * Valid response types.
     */
    private static final Set<String> VALID_RESPONSE_TYPES = Set.of("code", "id_token", "token", "id_token token");

    /**
     * The issuer identifier.
     */
    private final String issuer;

    /**
     * The ID Token generator.
     */
    private final IdTokenGenerator idTokenGenerator;

    /**
     * The user registry for authentication.
     */
    private final UserRegistry userRegistry;

    /**
     * The maximum authentication age in seconds.
     */
    private final Long maxAge;

    /**
     * Active authentication sessions.
     * <p>
     * Key: subject identifier
     * Value: last authentication timestamp
     * </p>
     */
    private final Map<String, Long> authenticationSessions;

    /**
     * Chain of authentication methods.
     * <p>
     * Each method is tried in order until one successfully authenticates the user.
     * This allows for flexible, pluggable authentication mechanisms.
     * </p>
     */
    private final List<AuthenticationMethod> authenticationMethods;

    /**
     * Creates a new DefaultAuthenticationProvider.
     *
     * @param idTokenGenerator the ID Token generator
     * @param userRegistry the user registry
     */
    public DefaultAuthenticationProvider(IdTokenGenerator idTokenGenerator, UserRegistry userRegistry) {
        this(idTokenGenerator, userRegistry, null, Collections.emptyList());
    }

    /**
     * Creates a new DefaultAuthenticationProvider with max age.
     *
     * @param idTokenGenerator the ID Token generator
     * @param userRegistry the user registry
     * @param maxAge the maximum authentication age in seconds, or null for no limit
     */
    public DefaultAuthenticationProvider(IdTokenGenerator idTokenGenerator, UserRegistry userRegistry, Long maxAge) {
        this(idTokenGenerator, userRegistry, maxAge, Collections.emptyList());
    }

    /**
     * Creates a new DefaultAuthenticationProvider with custom authentication methods.
     *
     * @param idTokenGenerator the ID Token generator
     * @param userRegistry the user registry
     * @param maxAge the maximum authentication age in seconds, or null for no limit
     * @param authenticationMethods the list of authentication methods to try
     */
    public DefaultAuthenticationProvider(
            IdTokenGenerator idTokenGenerator,
            UserRegistry userRegistry,
            Long maxAge,
            List<AuthenticationMethod> authenticationMethods) {

        // Validate and set the parameters
        this.idTokenGenerator = ValidationUtils.validateNotNull(idTokenGenerator, "ID Token generator");
        this.userRegistry = ValidationUtils.validateNotNull(userRegistry, "User registry");

        // Extract issuer from the generator if it's a DefaultIdTokenGenerator
        if (idTokenGenerator instanceof DefaultIdTokenGenerator) {
            this.issuer = ((DefaultIdTokenGenerator) idTokenGenerator).getIssuer();
        } else {
            throw new IllegalArgumentException("IdTokenGenerator must be an instance of DefaultIdTokenGenerator");
        }

        this.maxAge = maxAge;
        this.authenticationMethods = new ArrayList<>(ValidationUtils.validateNotNull(authenticationMethods, "Authentication methods"));
        this.authenticationSessions = new ConcurrentHashMap<>();

        logger.info("DefaultAuthenticationProvider initialized with issuer: {}, maxAge: {} seconds, {} authentication methods",
                issuer, maxAge, this.authenticationMethods.size());
    }

    /**
     * Authenticates the user.
     *
     * @param request the authentication request
     * @return the ID Token
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public IdToken authenticate(AuthenticationRequest request) {

        // Validate the parameters
        ValidationUtils.validateNotNull(request, "Authentication request");
        logger.debug("Processing authentication request for client: {}", request.getClientId());

        // Validate the request
        if (!validateRequest(request)) {
            throw new AuthenticationException(OidcRfcErrorCode.INVALID_REQUEST, "Invalid authentication request");
        }

        // Authenticate the user
        AuthenticationResult authResult = authenticateUser(request);

        // Check if the user is already authenticated and within max age
        if (isAuthenticated(authResult.getSubject()) && isAuthenticationValid(authResult.getSubject())) {
            logger.debug("User {} is already authenticated", authResult.getSubject());
        } else {
            // Record authentication
            logger.debug("Authenticating user {}", authResult.getSubject());
            recordAuthentication(authResult.getSubject());
        }

        // Build ID Token claims
        IdTokenClaims claims = buildIdTokenClaims(request, authResult);

        // Generate the ID Token
        IdToken idToken = idTokenGenerator.generate(claims);

        logger.info("Authentication successful for subject: {}, client: {}", authResult.getSubject(), request.getClientId());
        return idToken;
    }

    /**
     * Validates the authentication request.
     *
     * @param request the authentication request
     * @return true if the request is valid, false otherwise
     */
    @Override
    public boolean validateRequest(AuthenticationRequest request) {

        // Validate the parameters
        ValidationUtils.validateNotNull(request, "Authentication request");
        logger.debug("Validating authentication request");

        // Validate required basic parameters
        if (!validateBasicParameters(request)) {
            return false;
        }

        // Validate response type and flow-specific requirements
        if (!validateResponseTypeAndFlow(request)) {
            return false;
        }

        // Validate scope
        if (!validateScope(request)) {
            return false;
        }

        // Validate optional parameters
        if (!validateOptionalParameters(request)) {
            return false;
        }

        logger.debug("Authentication request validation successful");
        return true;
    }

    /**
     * Validates basic required parameters.
     *
     * @param request the authentication request
     * @return true if basic parameters are valid, false otherwise
     */
    private boolean validateBasicParameters(AuthenticationRequest request) {

        // Validate client ID
        if (request.getClientId() == null || request.getClientId().isEmpty()) {
            logger.warn("Client ID is missing");
            return false;
        }

        // Validate redirect URI
        if (request.getRedirectUri() == null || request.getRedirectUri().isEmpty()) {
            logger.warn("Redirect URI is missing");
            return false;
        }

        // Validate scope
        if (request.getScope() == null || request.getScope().isEmpty()) {
            logger.warn("Scope is missing");
            return false;
        }

        return true;
    }

    /**
     * Validates response type and flow-specific requirements.
     *
     * @param request the authentication request
     * @return true if response type and flow requirements are valid, false otherwise
     */
    private boolean validateResponseTypeAndFlow(AuthenticationRequest request) {

        // Validate response_type
        if (request.getResponseType() == null || request.getResponseType().isEmpty()) {
            logger.warn("Response type is missing");
            return false;
        }

        // Check if response_type is valid
        if (!VALID_RESPONSE_TYPES.contains(request.getResponseType())) {
            logger.warn("Invalid response type: {}", request.getResponseType());
            return false;
        }

        // For implicit flow, nonce is required
        if (request.isImplicitFlow() && (request.getNonce() == null || request.getNonce().isEmpty())) {
            logger.warn("Nonce is required for implicit flow");
            return false;
        }

        return true;
    }

    /**
     * Validates scope parameter.
     *
     * @param request the authentication request
     * @return true if scope is valid, false otherwise
     */
    private boolean validateScope(AuthenticationRequest request) {
        // Scope must include "openid"
        if (!request.hasOpenidScope()) {
            logger.warn("Scope must include 'openid'");
            return false;
        }
        return true;
    }

    /**
     * Validates optional parameters.
     *
     * @param request the authentication request
     * @return true if optional parameters are valid, false otherwise
     */
    private boolean validateOptionalParameters(AuthenticationRequest request) {
        // Validate max_age if present
        if (request.getMaxAge() != null && request.getMaxAge() <= 0) {
            logger.warn("Invalid max_age: {}", request.getMaxAge());
            return false;
        }
        return true;
    }

    /**
     * Checks if the user is authenticated.
     *
     * @param subject the subject identifier
     * @return true if the user is authenticated, false otherwise
     */
    @Override
    public boolean isAuthenticated(String subject) {
        ValidationUtils.validateNotNull(subject, "Subject");
        return authenticationSessions.containsKey(subject);
    }

    /**
     * Gets the maximum authentication age in seconds.
     *
     * @return the maximum authentication age in seconds, or null if no limit
     */
    @Override
    public Long getMaxAge() {
        return maxAge;
    }

    /**
     * Authenticates the user.
     * <p>
     * This method authenticates the user using a chain of authentication methods.
     * Each method is tried in order until one successfully authenticates the user.
     * If no method successfully authenticates the user, an exception is thrown.
     * </p>
     * <p>
     * <b>Authentication Chain:</b></p>
     * <ol>
     *   <li>Try each authentication method in the order they were registered</li>
     *   <li>If a method returns null, it indicates it's not applicable, so try the next</li>
     *   <li>If a method returns a result, authentication is successful</li>
     *   <li>If a method throws an exception, that exception is propagated</li>
     * </ol>
     *
     * @param request the authentication request
     * @return the authentication result containing subject and authentication method
     * @throws AuthenticationException if authentication fails
     */
    private AuthenticationResult authenticateUser(AuthenticationRequest request) {

        logger.debug("Attempting authentication with {} methods", authenticationMethods.size());
        for (AuthenticationMethod method : authenticationMethods) {
            try {
                AuthenticationResult result = method.authenticate(request, userRegistry);
                if (result != null) {
                    logger.debug("Authentication successful using method: {}", method.getClass().getSimpleName());
                    return result;
                }
            } catch (AuthenticationException e) {
                logger.warn("Authentication failed with method {}: {}", method.getClass().getSimpleName(), e.getMessage());
                throw e;
            }
        }

        // No authentication method available
        logger.debug("No authentication method succeeded");
        throw new AuthenticationException(OidcRfcErrorCode.INVALID_REQUEST, "Authentication credentials required");
    }

    /**
     * Checks if the authentication is still valid based on max age.
     *
     * @param subject the subject identifier
     * @return true if authentication is valid, false otherwise
     */
    private boolean isAuthenticationValid(String subject) {

        if (maxAge == null) {
            // No max age constraint
            return true;
        }

        Long lastAuthTime = authenticationSessions.get(subject);
        if (lastAuthTime == null) {
            return false;
        }

        long currentTime = Instant.now().getEpochSecond();
        long elapsed = currentTime - lastAuthTime;

        return elapsed <= maxAge;
    }

    /**
     * Records an authentication event for the subject.
     *
     * @param subject the subject identifier
     */
    private void recordAuthentication(String subject) {
        long currentTime = Instant.now().getEpochSecond();
        authenticationSessions.put(subject, currentTime);
        logger.debug("Recorded authentication for subject: {} at {}", subject, currentTime);
    }

    /**
     * Builds ID Token claims from the authentication request.
     *
     * @param request the authentication request
     * @param authResult the authentication result
     * @return the ID Token claims
     */
    private IdTokenClaims buildIdTokenClaims(AuthenticationRequest request, AuthenticationResult authResult) {

        // Get authentication time
        long currentTime = Instant.now().getEpochSecond();
        long authTime = authenticationSessions.getOrDefault(authResult.getSubject(), currentTime);

        // Calculate expiration time (use maxAge or default 1 hour)
        long exp = currentTime + (maxAge != null ? maxAge : 3600);

        // Build ID Token claims
        IdTokenClaims.Builder claimsBuilder = IdTokenClaims.builder()
                .iss(issuer)
                .sub(authResult.getSubject())
                .aud(request.getClientId())
                .iat(currentTime)
                .exp(exp)
                .authTime(authTime);

        // Add nonce if present
        if (request.getNonce() != null) {
            claimsBuilder.nonce(request.getNonce());
        }

        // Add acr if present in request
        if (request.getAcrValues() != null) {
            String[] acrValues = request.getAcrValues().split(" ");
            if (acrValues.length > 0) {
                claimsBuilder.acr(acrValues[0]);
            }
        }

        // Add amr (authentication methods references) from actual authentication
        claimsBuilder.amr(authResult.getAuthenticationMethods());

        // Add azp (authorized party) if needed
        // For implicit flow, azp should be the client ID
        if (request.isImplicitFlow()) {
            claimsBuilder.azp(request.getClientId());
        }

        // Add additional claims if needed
        Map<String, Object> additionalClaims = new HashMap<>();
        claimsBuilder.additionalClaims(additionalClaims);

        return claimsBuilder.build();
    }

    /**
     * Gets the ID Token generator.
     *
     * @return the ID Token generator
     */
    public IdTokenGenerator getIdTokenGenerator() {
        return idTokenGenerator;
    }

    /**
     * Gets the active authentication sessions.
     *
     * @return a copy of the authentication sessions map
     */
    public Map<String, Long> getAuthenticationSessions() {
        return new HashMap<>(authenticationSessions);
    }

    /**
     * Gets the user registry.
     *
     * @return the user registry
     */
    public UserRegistry getUserRegistry() {
        return userRegistry;
    }

    /**
     * Gets the authentication methods chain.
     *
     * @return an unmodifiable list of authentication methods
     */
    public List<AuthenticationMethod> getAuthenticationMethods() {
        return Collections.unmodifiableList(authenticationMethods);
    }

}
