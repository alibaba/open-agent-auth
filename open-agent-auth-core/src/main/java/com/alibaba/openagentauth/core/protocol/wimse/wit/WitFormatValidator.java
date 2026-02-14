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

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.util.ValidationUtils;

/**
 * Utility class for validating Workload Identity Token (WIT) format.
 * <p>
 * This class provides methods to validate the basic format of WIT strings,
 * ensuring they are properly formatted JWT tokens before further processing.
 * </p>
 * <p>
 * This is a lightweight format validator that only checks the JWT structure.
 * For full signature and claims validation, use {@code WitValidator} from
 * the token.validation package.
 * </p>
 *
 * @since 1.0
 */
public final class WitFormatValidator {

    /**
     * Private constructor to prevent instantiation.
     */
    private WitFormatValidator() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Validates the format of a Workload Identity Token.
     * <p>
     * This method checks that the WIT is a properly formatted JWT with three parts
     * (header, payload, signature). It does not verify the signature or validate
     * claims.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @throws DcrException if the format is invalid
     * @throws IllegalArgumentException if wit is null or empty
     */
    public static void validateFormat(String wit) throws DcrException {
        if (ValidationUtils.isNullOrEmpty(wit)) {
            throw new IllegalArgumentException("WIT cannot be null or empty");
        }

        String[] parts = wit.split(WitConstants.JWT_DELIMITER);
        if (parts.length != WitConstants.JWT_PARTS_COUNT) {
            throw DcrException.invalidClientMetadata(
                String.format("Invalid WIT format: expected JWT with %d parts, got %d",
                    WitConstants.JWT_PARTS_COUNT, parts.length)
            );
        }
    }
}
