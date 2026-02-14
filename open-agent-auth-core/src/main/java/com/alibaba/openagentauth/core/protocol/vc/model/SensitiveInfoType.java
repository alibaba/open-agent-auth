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
 * Enumeration of sensitive information types that can be detected in user prompts.
 * <p>
 * This enum defines the standard categories of sensitive information that the
 * prompt sanitization mechanism can identify and handle. Each type is associated
 * with a severity level that determines the default sanitization strategy.
 * </p>
 * <p>
 * The severity levels follow privacy-by-design principles:
 * <ul>
 *   <li>HIGH: Personally Identifiable Information (PII) that requires mandatory sanitization</li>
 *   <li>MEDIUM: Contact information that should be sanitized by default</li>
 *   <li>LOW: Personal preferences that can be sanitized based on user preference</li>
 * </ul>
 * </p>
 * <p>
 * This enum is immutable and thread-safe, following Effective Java Item 15.
 * </p>
 *
 * @since 1.0
 * @see Severity
 * @see SensitiveInfo
 */
public enum SensitiveInfoType {
    
    /**
     * Mobile phone number in Chinese format (11 digits starting with 1).
     * <p>
     * Example: 13800138000
     * Pattern: 1[3-9]\d{9}
     * </p>
     */
    PHONE_NUMBER("Mobile Phone Number", Severity.HIGH),
    
    /**
     * Email address following RFC 5322 format.
     * <p>
     * Example: user@example.com
     * Pattern: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
     * </p>
     */
    EMAIL("Email Address", Severity.MEDIUM),
    
    /**
     * Chinese Resident Identity Card number (18 digits).
     * <p>
     * Example: 110101199001011234
     * Pattern: \d{17}[\dXx]
     * </p>
     */
    ID_CARD("Chinese ID Card", Severity.HIGH),
    
    /**
     * Bank card number (typically 16-19 digits).
     * <p>
     * Example: 6222021234567890123
     * Pattern: \d{13,19}
     * </p>
     */
    BANK_CARD("Bank Card Number", Severity.HIGH),
    
    /**
     * Budget or price range information.
     * <p>
     * Example: "Budget between 500-1000 dollars"
     * Pattern: [Bb]udget.*\d+.*
     * </p>
     */
    BUDGET("Budget Range", Severity.LOW),
    
    /**
     * Physical address information.
     * <p>
     * Example: "123 Main Street, Beijing, Chaoyang District"
     * Pattern: \d+\s+[A-Za-z\s]+,?\s*[A-Za-z\s]+
     * </p>
     */
    ADDRESS("Physical Address", Severity.MEDIUM),
    
    /**
     * Personal name.
     * <p>
     * Example: "John Smith" or "Zhang San"
     * Pattern: [A-Z][a-z]+ [A-Z][a-z]+
     * </p>
     */
    NAME("Personal Name", Severity.MEDIUM),
    
    /**
     * Custom sensitive information type for extensibility.
     * <p>
     * This type allows users to define custom sensitive information patterns
     * through configuration. It follows the Open/Closed Principle by enabling
     * extension without modification.
     * </p>
     */
    CUSTOM("Custom Sensitive Info", Severity.MEDIUM);

    /**
     * Human-readable display name for this sensitive information type.
     * <p>
     * This field is used in user-facing UI to describe the type of sensitive
     * information detected.
     * </p>
     */
    private final String displayName;
    
    /**
     * The severity level associated with this sensitive information type.
     * <p>
     * Severity determines the default sanitization strategy and whether
     * sanitization is mandatory, recommended, or optional.
     * </p>
     */
    private final Severity severity;

    /**
     * Constructs a new SensitiveInfoType with the specified display name and severity.
     *
     * @param displayName the human-readable display name for this type
     * @param severity the severity level associated with this type
     */
    SensitiveInfoType(String displayName, Severity severity) {
        this.displayName = displayName;
        this.severity = severity;
    }

    /**
     * Returns the human-readable display name for this sensitive information type.
     *
     * @return the display name
     */
    public String getDisplayName() {
        return displayName;
    }

    /**
     * Returns the severity level associated with this sensitive information type.
     *
     * @return the severity level
     */
    public Severity getSeverity() {
        return severity;
    }
}
