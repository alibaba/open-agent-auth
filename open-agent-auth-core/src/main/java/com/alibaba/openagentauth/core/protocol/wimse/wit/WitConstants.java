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

/**
 * Constants for Workload Identity Token (WIT) handling.
 * <p>
 * This class contains the constant values used across the codebase for
 * WIT-related operations, ensuring consistency and avoiding duplication.
 * </p>
 * <p>
 * These constants are based on the WIMSE protocol specification:
 * <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">
 *     draft-ietf-wimse-workload-creds</a>
 * </p>
 *
 * @since 1.0
 */
public final class WitConstants {

    /**
     * Private constructor to prevent instantiation.
     */
    private WitConstants() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Parameter name for the Workload Identity Token in DCR requests.
     */
    public static final String WIT_PARAM = "wit";

    /**
     * HTTP header name for the Workload Identity Token as per WIMSE specification.
     */
    public static final String WIT_HEADER_NAME = "Workload-Identity-Token";

    /**
     * Expected JWT parts count (header.payload.signature).
     */
    public static final int JWT_PARTS_COUNT = 3;

    /**
     * JWT delimiter.
     */
    public static final String JWT_DELIMITER = "\\.";
}
