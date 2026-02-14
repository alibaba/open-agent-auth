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
 * Enumeration of sanitization levels for sensitive information handling.
 * <p>
 * This enum defines the intensity levels for sanitizing sensitive information
 * in user prompts. Each level represents a different approach to balancing
 * privacy protection with information utility.
 * </p>
 * <p>
 * The sanitization levels are designed to provide flexibility for different
 * use cases while maintaining strong security guarantees:
 * <ul>
 *   <li>NONE: No sanitization applied (use with caution)</li>
 *   <li>LOW: Partial masking preserving some information</li>
 *   <li>MEDIUM: Standard masking with common patterns</li>
 *   <li>HIGH: Complete replacement with generic placeholders</li>
 * </ul>
 * </p>
 * <p>
 * This enum is immutable and thread-safe, following Effective Java Item 15.
 * </p>
 *
 * @since 1.0
 */
public enum SanitizationLevel {
    
    /**
     * No sanitization applied.
     * <p>
     * This level should only be used when explicitly requested by the user
     * or in trusted environments where privacy concerns are minimal.
     * </p>
     * <p>
     * Warning: Using this level may expose sensitive information.
     * </p>
     */
    NONE,
    
    /**
     * Low-level sanitization with partial masking.
     * <p>
     * This level preserves some information while masking the most sensitive
     * parts. Examples:
     * <ul>
     *   <li>Phone: 13800138000 → 138****8000</li>
     *   <li>Email: user@example.com → u***@example.com</li>
     * </ul>
     * </p>
     * <p>
     * This level is suitable for debugging and auditing purposes where
     * some identification is still needed.
     * </p>
     */
    LOW,
    
    /**
     * Medium-level sanitization with standard masking patterns.
     * <p>
     * This level applies common masking patterns that balance privacy
     * with information utility. Examples:
     * <ul>
     *   <li>Phone: 13800138000 → 138***8000</li>
     *   <li>Email: user@example.com → te***@example.com</li>
     *   <li>ID: 110101199001011234 → 110***********1234</li>
     * </ul>
     * </p>
     * <p>
     * This is the recommended default level for most use cases.
     * </p>
     */
    MEDIUM,
    
    /**
     * High-level sanitization with complete replacement.
     * <p>
     * This level replaces all sensitive information with generic placeholders.
     * Examples:
     * <ul>
     *   <li>Phone: 13800138000 → [PHONE_NUMBER_REDACTED]</li>
     *   <li>Email: user@example.com → [EMAIL_REDACTED]</li>
     *   <li>Budget: Budget 500-1000 dollars → [BUDGET_REDACTED]</li>
     * </ul>
     * </p>
     * <p>
     * This level provides maximum privacy protection and is recommended for
     * production environments with high security requirements.
     * </p>
     */
    HIGH;

    /**
     * Determines if this sanitization level applies any masking.
     *
     * @return true if this level applies masking, false if NONE
     */
    public boolean isMaskingEnabled() {
        return this != NONE;
    }
}
