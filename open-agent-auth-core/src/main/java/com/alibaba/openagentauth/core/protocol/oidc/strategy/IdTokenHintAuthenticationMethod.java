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

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.exception.oidc.OidcRfcErrorCode;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ID Token hint-based authentication method strategy.
 * <p>
 * This implementation authenticates users using the id_token_hint parameter,
 * which contains a previously issued ID token. The subject is extracted from
 * the validated token and used for re-authentication purposes.
 * </p>
 * <p>
 * <b>Authentication Method Reference:</b> id_token
 * </p>
 * <p>
 * <b>Security:</b> This implementation performs full JWT validation including
 * signature verification, expiration check, issuer validation, and audience validation
 * before extracting the subject. This ensures that only valid, unexpired tokens
 * issued by trusted identity providers are accepted.
 * </p>
 *
 * @since 1.0
 */
public class IdTokenHintAuthenticationMethod implements AuthenticationMethod {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(IdTokenHintAuthenticationMethod.class);

    /**
     * The ID token validator for JWT validation.
     */
    private final IdTokenValidator idTokenValidator;

    /**
     * Creates a new IdTokenHintAuthenticationMethod with the specified validator.
     *
     * @param idTokenValidator the ID token validator for JWT validation
     * @throws IllegalArgumentException if idTokenValidator is null
     */
    public IdTokenHintAuthenticationMethod(IdTokenValidator idTokenValidator) {
        this.idTokenValidator = ValidationUtils.validateNotNull(idTokenValidator, "ID token validator");
    }

    /**
     * Attempts to authenticate using id_token_hint parameter.
     *
     * @param request the authentication request
     * @param userRegistry the user registry (not used in this method)
     * @return the authentication result if id_token_hint is present and valid, null otherwise
     * @throws AuthenticationException if the ID token is invalid
     */
    @Override
    public AuthenticationResult authenticate(AuthenticationRequest request, UserRegistry userRegistry) throws AuthenticationException {
        String idTokenHint = request.getIdTokenHint();

        // Return null if id_token_hint is not present (this method is not applicable)
        if (ValidationUtils.isNullOrEmpty(idTokenHint)) {
            return null;
        }

        // Validate the ID token hint
        try {
            logger.debug("Validating id_token_hint");

            // Validate using the ID token validator
            // Note: For id_token_hint, we typically don't validate nonce as it's a re-authentication scenario
            var validatedToken = idTokenValidator.validate(
                    idTokenHint,
                    request.getClientId(),  // Use client ID as expected audience
                    request.getClientId()   // Use client ID as expected issuer (or configured issuer)
            );

            String subject = validatedToken.getClaims().getSub();
            logger.debug("id_token_hint validated successfully for subject: {}", subject);

            return new AuthenticationResult(subject, new String[]{"id_token"});

        } catch (IdTokenException e) {
            logger.warn("id_token_hint validation failed: {}", e.getMessage());
            throw new AuthenticationException(OidcRfcErrorCode.INVALID_ID_TOKEN_HINT, "Invalid ID token hint: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the ID token validator.
     *
     * @return the ID token validator
     */
    public IdTokenValidator getIdTokenValidator() {
        return idTokenValidator;
    }
}