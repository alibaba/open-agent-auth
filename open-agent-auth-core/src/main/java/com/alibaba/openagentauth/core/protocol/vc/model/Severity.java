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
package com.alibaba.openagentauth.core.protocol.vc.model;

/**
 * Enumeration of severity levels for sensitive information.
 * <p>
 * This enum defines the severity levels used to classify sensitive information
 * detected in user prompts. The severity level determines the default handling
 * strategy and user experience for the sanitization mechanism.
 * </p>
 * <p>
 * Severity levels follow a graduated approach:
 * <ul>
 *   <li>LOW: Information that users may choose to share (e.g., budget preferences)</li>
 *   <li>MEDIUM: Information that should be protected but has alternatives (e.g., email)</li>
 *   <li>HIGH: Information that must be protected (e.g., ID cards, bank numbers)</li>
 * </ul>
 * </p>
 * <p>
 * This enum is immutable and thread-safe, following Effective Java Item 15.
 * </p>
 *
 * @since 1.0
 * @see SensitiveInfoType
 */
public enum Severity {
    
    /**
     * Low severity level.
     * <p>
     * Information classified as LOW severity typically includes personal preferences
     * or non-identifying data that users may be comfortable sharing. Examples include
     * budget ranges, shopping preferences, or general interests.
     * </p>
     * <p>
     * Default behavior: Optional sanitization with user choice.
     * </p>
     */
    LOW,
    
    /**
     * Medium severity level.
     * <p>
     * Information classified as MEDIUM severity includes contact information and
     * personally identifiable information that has alternatives. Examples include
     * email addresses, phone numbers, and physical addresses.
     * </p>
     * <p>
     * Default behavior: Recommended sanitization with user override option.
     * </p>
     */
    MEDIUM,
    
    /**
     * High severity level.
     * <p>
     * Information classified as HIGH severity includes critical personally
     * identifiable information that must be protected. Examples include ID card
     * numbers, bank card numbers, and government identifiers.
     * </p>
     * <p>
     * Default behavior: Mandatory sanitization without user override.
     * </p>
     */
    HIGH;

    /**
     * Determines if this severity level requires mandatory sanitization.
     *
     * @return true if this is HIGH severity, false otherwise
     */
    public boolean isMandatory() {
        return this == HIGH;
    }

    /**
     * Determines if this severity level recommends sanitization by default.
     *
     * @return true if this is MEDIUM or HIGH severity, false otherwise
     */
    public boolean isRecommended() {
        return this == MEDIUM || this == HIGH;
    }
}
