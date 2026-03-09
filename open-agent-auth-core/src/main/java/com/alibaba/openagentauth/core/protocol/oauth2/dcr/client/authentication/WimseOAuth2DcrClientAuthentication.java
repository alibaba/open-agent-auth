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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitConstants;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitExtractor;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpRequest;

/**
 * WIMSE-based DCR client authentication using Software Statement (OAuth 2.0 Dynamic Client Registration).
 * <p>
 * This implementation applies WIMSE (Workload Identity Management for Service Environments)
 * authentication to DCR requests using the standard {@code software_statement} mechanism
 * defined in RFC 7591 "OAuth 2.0 Dynamic Client Registration Protocol".
 * </p>
 * <p>
 * <b>Authentication Flow:</b></p>
 * <p>
 * The Workload Identity Token (WIT) is used as the {@code software_statement} JWT in the
 * DCR request body. This follows the Software Statement pattern for dynamic client registration,
 * where the software statement contains signed metadata about the client software.
 * </p>
 * <p>
 * <b>Request Processing:</b></p>
 * <ul>
 *   <li>If {@code DcrRequest.softwareStatement} is already set (via Builder), the method simply
 *       cleans up the legacy {@code wit} parameter from additionalParameters.</li>
 *   <li>If not set (for backward compatibility), the method extracts the WIT from the
 *       {@code wit} parameter and places it in {@code software_statement} key.</li>
 * </ul>
 * <p>
 * The Authorization Server validates the software statement signature and claims before
 * registering the client. The WIT's {@code sub} claim (workload identity) is used as the
 * {@code client_id}, binding the OAuth client to the workload identity.
 * </p>
 *
 * @see OAuth2DcrClientAuthentication
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration Protocol</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">
 *     draft-ietf-wimse-workload-creds - Workload Identity Credentials</a>
 * @since 1.0
 */
public class WimseOAuth2DcrClientAuthentication implements OAuth2DcrClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(WimseOAuth2DcrClientAuthentication.class);

    /**
     * The OAuth 2.0 parameter name for software statement (RFC 7591).
     */
    private static final String SOFTWARE_STATEMENT_PARAM = "software_statement";

    /**
     * Creates a new WIMSE DCR client authentication.
     */
    public WimseOAuth2DcrClientAuthentication() {
        logger.debug("WimseDcrClientAuthentication initialized");
    }

    @Override
    public HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, DcrRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(requestBuilder, "Request builder");
        ValidationUtils.validateNotNull(request, "DCR request");

        logger.debug("Applying WIMSE software statement authentication to DCR request");

        // Check if software_statement is already set via Builder (preferred path)
        if (request.getSoftwareStatement() != null && !request.getSoftwareStatement().trim().isEmpty()) {
            logger.debug("Software statement already set in DcrRequest, cleaning up legacy wit parameter");
            // Clean up legacy 'wit' parameter if present
            if (request.getAdditionalParameters() != null) {
                request.getAdditionalParameters().remove(WitConstants.WIT_PARAM);
            }
            return requestBuilder;
        }

        // Backward compatibility: extract WIT from additional parameters and place in software_statement
        String wit = WitExtractor.extractFromDcrRequest(request);

        if (ValidationUtils.isNullOrEmpty(wit)) {
            logger.debug("No WIT found in request, skipping WIMSE authentication");
            return requestBuilder;
        }

        // Place the WIT in software_statement parameter
        // The @JsonAnyGetter on DcrRequest will flatten this into the top-level JSON body
        if (request.getAdditionalParameters() != null) {
            request.getAdditionalParameters().remove(WitConstants.WIT_PARAM);
            request.getAdditionalParameters().put(SOFTWARE_STATEMENT_PARAM, wit);
        }

        logger.debug("WIMSE software statement authentication applied: WIT set as software_statement in request body");

        return requestBuilder;
    }

    @Override
    public String getAuthenticationMethod() {
        return "software_statement";
    }
}