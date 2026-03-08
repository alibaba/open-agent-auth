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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.Map;

/**
 * Utility class for extracting Workload Identity Tokens (WIT) from requests.
 * <p>
 * This class provides methods to extract WIT from various request types,
 * ensuring consistent extraction logic across the codebase.
 * </p>
 *
 * @since 1.0
 */
public final class WitExtractor {

    /**
     * Private constructor to prevent instantiation.
     */
    private WitExtractor() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * The OAuth 2.0 parameter name for software statement (RFC 7591).
     */
    private static final String SOFTWARE_STATEMENT_PARAM = "software_statement";

    /**
     * Extracts the Workload Identity Token (WIT) from a DCR request.
     * <p>
     * This method supports multiple extraction modes with the following priority order:
     * </p>
     * <ol>
     *   <li><b>Software Statement mode (highest priority)</b>: The WIT is sent as a
     *       {@code software_statement} parameter in {@code DcrRequest.softwareStatement} field.
     *       This is the preferred mode for WIMSE + DCR integration (RFC 7591 Section 2.3).</li>
     *   <li><b>Software Statement in additionalParameters</b>: The WIT is sent under the
     *       {@code software_statement} key in {@code additionalParameters} for backward compatibility.</li>
     *   <li><b>Legacy wit mode (fallback)</b>: The WIT is sent under the {@code wit} key
     *       in {@code additionalParameters}.</li>
     * </ol>
     *
     * @param request the DCR request
     * @return the WIT string, or null if not present
     * @throws IllegalArgumentException if request is null
     */
    public static String extractFromDcrRequest(DcrRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(request, "DCR request");

        // Priority 1: Extract from DcrRequest.softwareStatement field (preferred path)
        if (request.getSoftwareStatement() != null && !request.getSoftwareStatement().trim().isEmpty()) {
            return request.getSoftwareStatement();
        }

        // Extract WIT from additional parameters
        Map<String, Object> additionalParameters = request.getAdditionalParameters();
        if (additionalParameters == null) {
            return null;
        }

        // Priority 2: Extract from software_statement in additionalParameters (backward compatibility)
        Object softwareStatementObj = additionalParameters.get(SOFTWARE_STATEMENT_PARAM);
        if (softwareStatementObj instanceof String softwareStatement && !softwareStatement.trim().isEmpty()) {
            return softwareStatement;
        }

        // Priority 3: Fall back to legacy "wit" parameter
        Object witObj = additionalParameters.get(WitConstants.WIT_PARAM);
        if (witObj instanceof String) {
            return (String) witObj;
        }

        return null;
    }

    /**
     * Checks if a DCR request contains a valid WIT.
     * <p>
     * A valid WIT must be present and non-empty. This method checks all supported
     * extraction modes: software_statement and legacy wit parameter.
     * </p>
     *
     * @param request the DCR request
     * @return true if the request contains a valid WIT, false otherwise
     * @throws IllegalArgumentException if request is null
     */
    public static boolean hasWitInDcrRequest(DcrRequest request) {
        String wit = extractFromDcrRequest(request);
        return wit != null && !wit.trim().isEmpty();
    }
}