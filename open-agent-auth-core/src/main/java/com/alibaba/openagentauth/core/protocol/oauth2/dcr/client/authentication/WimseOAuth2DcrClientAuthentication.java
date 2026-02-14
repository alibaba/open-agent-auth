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
 * WIMSE-based DCR client authentication.
 * <p>
 * This implementation applies WIMSE (Workload Identity Management for Service Environments)
 * authentication to DCR requests. It extracts the Workload Identity Token (WIT) from the
 * request's additional parameters and adds it in the Workload-Identity-Token header.
 * </p>
 * <p>
 * <b>WIMSE Authentication:</b></p>
 * <p>
 * When registering a client with a WIT, the WIT is included in the Workload-Identity-Token
 * HTTP header. The Authorization Server validates the WIT signature and claims before
 * registering the client. This binds the OAuth client to the workload identity specified
 * in the WIT.
 * </p>
 *
 * @see OAuth2DcrClientAuthentication
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">
 *     draft-ietf-wimse-workload-creds - Workload Identity Credentials</a>
 * @since 1.0
 */
public class WimseOAuth2DcrClientAuthentication implements OAuth2DcrClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(WimseOAuth2DcrClientAuthentication.class);

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

        logger.debug("Applying WIMSE authentication to DCR request");

        // Extract WIT from additional parameters
        String wit = WitExtractor.extractFromDcrRequest(request);

        if (!ValidationUtils.isNullOrEmpty(wit)) {
            // Add WIT in Workload-Identity-Token header as per WIMSE specification
            requestBuilder.header(WitConstants.WIT_HEADER_NAME, wit);
            logger.debug("WIMSE authentication applied: WIT present in request");
        } else {
            logger.debug("No WIT found in request, skipping WIMSE authentication");
        }

        return requestBuilder;
    }

    @Override
    public String getAuthenticationMethod() {
        return "private_key_jwt";
    }
}