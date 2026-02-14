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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpRequest;

/**
 * No authentication DCR client authentication.
 * <p>
 * This implementation applies no authentication to DCR requests. It is used for
 * scenarios where the Authorization Server does not require authentication for
 * initial client registration, or when authentication is handled through other
 * mechanisms (e.g., TLS client certificates).
 * </p>
 * <p>
 * <b>Use Cases:</b></p>
 * <ul>
 *   <li>Initial registration when AS allows unauthenticated requests</li>
 *   <li>Development and testing environments</li>
 *   <li>When TLS mutual authentication is used instead of HTTP headers</li>
 * </ul>
 *
 * @see OAuth2DcrClientAuthentication
 * @since 1.0
 */
public class NoAuthOAuth2DcrClientAuthentication implements OAuth2DcrClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(NoAuthOAuth2DcrClientAuthentication.class);

    /**
     * Creates a new no authentication DCR client authentication.
     */
    public NoAuthOAuth2DcrClientAuthentication() {
        logger.debug("NoAuthDcrClientAuthentication initialized");
    }

    @Override
    public HttpRequest.Builder applyAuthentication(HttpRequest.Builder requestBuilder, DcrRequest request) {
        ValidationUtils.validateNotNull(requestBuilder, "Request builder");
        ValidationUtils.validateNotNull(request, "DCR request");

        logger.debug("Applying no authentication to DCR request");
        
        // No authentication headers are added
        return requestBuilder;
    }

    @Override
    public String getAuthenticationMethod() {
        return "none";
    }
}