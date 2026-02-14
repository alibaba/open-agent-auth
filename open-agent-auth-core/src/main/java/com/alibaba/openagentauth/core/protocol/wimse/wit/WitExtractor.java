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
     * Extracts the Workload Identity Token (WIT) from a DCR request.
     * <p>
     * The WIT is stored in the additionalParameters map under the "wit" key
     * as part of the WIMSE protocol extension.
     * </p>
     *
     * @param request the DCR request
     * @return the WIT string, or null if not present
     * @throws IllegalArgumentException if request is null
     */
    public static String extractFromDcrRequest(DcrRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(request, "DCR request");

        // Extract WIT from additional parameters
        Map<String, Object> additionalParameters = request.getAdditionalParameters();
        if (additionalParameters == null) {
            return null;
        }

        // Extract WIT from additional parameters
        Object witObj = additionalParameters.get(WitConstants.WIT_PARAM);
        if (witObj instanceof String) {
            return (String) witObj;
        }

        return null;
    }

    /**
     * Checks if a DCR request contains a valid WIT.
     * <p>
     * A valid WIT must be present and non-empty. Empty strings are considered invalid
     * according to WIMSE protocol requirements.
     * </p>
     *
     * @param request the DCR request
     * @return true if the request contains a valid WIT, false otherwise
     * @throws IllegalArgumentException if request is null
     */
    public static boolean hasWitInDcrRequest(DcrRequest request) {
        ValidationUtils.validateNotNull(request, "DCR request");

        Map<String, Object> additionalParameters = request.getAdditionalParameters();
        if (additionalParameters == null) {
            return false;
        }

        Object witObj = additionalParameters.get(WitConstants.WIT_PARAM);
        if (witObj instanceof String wit) {
            return !wit.trim().isEmpty();
        }

        return false;
    }
}