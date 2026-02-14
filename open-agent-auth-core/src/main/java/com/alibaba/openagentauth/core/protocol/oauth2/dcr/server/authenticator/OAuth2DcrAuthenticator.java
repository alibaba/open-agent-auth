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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.authenticator;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;

/**
 * Strategy interface for DCR client authentication.
 * <p>
 * This interface defines the contract for authenticating client registration requests
 * using different protocols. Implementations can support various authentication methods
 * such as WIMSE, SPIFFE, or standard OAuth 2.0 client authentication.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern</p>
 * <p>
 * This interface allows the DCR server to support pluggable authentication mechanisms
 * without modifying the core registration logic. Each implementation handles the
 * specific validation and authentication requirements of its protocol.
 * </p>
 * <p>
 * <b>Implementation Examples:</b></p>
 * <ul>
 *   <li>{@code WimseDcrAuthenticator} - WIMSE protocol with Workload Identity Token</li>
 *   <li>{@code SpiffeDcrAuthenticator} - SPIFFE protocol with SVID</li>
 *   <li>{@code StandardDcrAuthenticator} - Standard OAuth 2.0 client authentication</li>
 * </ul>
 *
 * @see WimseOAuth2DcrAuthenticator
 * @since 1.0
 */
public interface OAuth2DcrAuthenticator {

    /**
     * Authenticates a DCR request using the specific protocol's authentication mechanism.
     * <p>
     * This method validates the client's identity and credentials according to the
     * protocol's requirements. If authentication fails, a {@link DcrException} is thrown.
     * </p>
     * <p>
     * <b>Authentication Flow:</b></p>
     * <ol>
     *   <li>Extract authentication credentials from the request</li>
     *   <li>Validate credential format and structure</li>
     *   <li>Verify cryptographic signatures (if applicable)</li>
     *   <li>Extract and validate identity claims</li>
     *   <li>Return the authenticated subject identifier</li>
     * </ol>
     *
     * @param request the DCR request to authenticate
     * @return the authenticated subject identifier
     * @throws DcrException if authentication fails
     */
    String authenticate(DcrRequest request) throws DcrException;

    /**
     * Checks if this authenticator can handle the given DCR request.
     * <p>
     * This method allows the DCR server to determine which authenticator to use
     * for a specific request. Implementations should check for the presence of
     * protocol-specific parameters or authentication method indicators.
     * </p>
     *
     * @param request the DCR request to check
     * @return true if this authenticator can handle the request, false otherwise
     */
    boolean canAuthenticate(DcrRequest request);

    /**
     * Gets the authentication method name for this authenticator.
     * <p>
     * This method returns a string identifier for the authentication method,
     * typically matching the {@code token_endpoint_auth_method} value used in
     * OAuth 2.0 client metadata.
     * </p>
     *
     * @return the authentication method name
     */
    String getAuthenticationMethod();

}
