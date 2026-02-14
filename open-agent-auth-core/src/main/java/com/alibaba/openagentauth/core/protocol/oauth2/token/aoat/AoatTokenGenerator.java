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
package com.alibaba.openagentauth.core.protocol.oauth2.token.aoat;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.nimbusds.jose.JOSEException;

/**
 * Interface for generating Agent Operation Authorization Tokens (AOAT).
 * <p>
 * This interface defines the contract for AOAT-specific token generation logic,
 * which involves:
 * </p>
 * <ul>
 *   <li>Extracting and parsing PAR claims</li>
 *   <li>Building AgentIdentity</li>
 *   <li>Building AgentOperationAuthorization</li>
 *   <li>Verifying Evidence VC</li>
 *   <li>Building TokenAuthorizationContext</li>
 *   <li>Building AuditTrail</li>
 *   <li>Generating the final AOAT JWT</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
public interface AoatTokenGenerator {

    /**
     * Generates an Agent Operation Authorization Token.
     *
     * @param subject the user subject
     * @param parClaims the PAR claims
     * @return the generated AOAT
     * @throws JOSEException if token generation fails
     * @throws OAuth2TokenException if validation fails
     */
    AgentOperationAuthToken generateAoat(String subject, ParJwtClaims parClaims) throws JOSEException;

}
