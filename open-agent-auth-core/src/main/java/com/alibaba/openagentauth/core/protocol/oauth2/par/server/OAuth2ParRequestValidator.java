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
package com.alibaba.openagentauth.core.protocol.oauth2.par.server;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;

/**
 * Validator for Pushed Authorization Requests.
 * <p>
 * This interface defines the contract for validating PAR requests
 * according to RFC 9126 and RFC 9101 specifications.
 * </p>
 * <p>
 * <b>Validation Requirements:</b></p>
 * <ul>
 *   <li><b>JWT Signature:</b> Verify the request JWT signature</li>
 *   <li><b>JWT Claims:</b> Validate iss, aud, exp, iat claims</li>
 *   <li><b>OAuth 2.0 Parameters:</b> Validate response_type, client_id, redirect_uri</li>
 *   <li><b>Scope:</b> Validate requested scope(s)</li>
 *   <li><b>PKCE:</b> Validate code_challenge if present (RFC 7636)</li>
 * </ul>
 *
 * @since 1.0
 */
public interface OAuth2ParRequestValidator {

    /**
     * Validates a PAR request.
     *
     * @param request the PAR request to validate
     * @throws ParException if validation fails
     * @throws IllegalArgumentException if request is null
     */
    void validate(ParRequest request);
}
