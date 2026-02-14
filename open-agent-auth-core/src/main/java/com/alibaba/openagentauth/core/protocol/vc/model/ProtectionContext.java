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

import java.util.Objects;

/**
 * Context information for prompt protection processing.
 * <p>
 * This class encapsulates all contextual information needed for the
 * prompt protection mechanism to make appropriate decisions about
 * detection, sanitization, and user presentation. It follows the
 * Context Object pattern from Domain-Driven Design.
 * </p>
 * <p>
 * The protection context includes:
 * <ul>
 *   <li>The original user prompt text</li>
 *   <li>The user's identity and session information</li>
 *   <li>Configuration preferences for protection behavior</li>
 *   <li>Metadata about the current operation</li>
 * </ul>
 * </p>
 * <p>
 * This class is immutable and thread-safe, following Effective Java Item 15.
 * </p>
 *
 * @since 1.0
 */
public class ProtectionContext {
    
    /**
     * The original prompt text submitted by the user.
     */
    private final String originalPrompt;
    
    /**
     * The preferred sanitization level for this context.
     * <p>
     * If null, the system default will be used.
     * </p>
     */
    private final SanitizationLevel preferredLevel;
    
    /**
     * Flag indicating whether JWE encryption should be applied.
     * <p>
     * If true, the prompt will be encrypted using JWE before transmission.
     * </p>
     */
    private final boolean enableEncryption;
    
    /**
     * Flag indicating whether user confirmation is required.
     * <p>
     * If true, the user must explicitly confirm before the prompt is
     * submitted, even if no sensitive information is detected.
     * </p>
     */
    private final boolean requireConfirmation;

    /**
     * Constructs a new ProtectionContext with the specified properties.
     *
     * @param originalPrompt the original prompt text
     * @param preferredLevel the preferred sanitization level (may be null)
     * @param enableEncryption whether to enable JWE encryption
     * @param requireConfirmation whether to require user confirmation
     * @throws NullPointerException if originalPrompt is null
     * @throws IllegalArgumentException if originalPrompt is empty
     */
    public ProtectionContext(String originalPrompt,
                             SanitizationLevel preferredLevel,
                             boolean enableEncryption,
                             boolean requireConfirmation) {
        this.originalPrompt = Objects.requireNonNull(originalPrompt, "Original prompt cannot be null");
        
        if (originalPrompt.trim().isEmpty()) {
            throw new IllegalArgumentException("Original prompt cannot be empty");
        }
        
        this.preferredLevel = preferredLevel;
        this.enableEncryption = enableEncryption;
        this.requireConfirmation = requireConfirmation;
    }

    /**
     * Returns the original prompt text.
     *
     * @return the original prompt text
     */
    public String getOriginalPrompt() {
        return originalPrompt;
    }

    /**
     * Returns the preferred sanitization level.
     *
     * @return the preferred sanitization level, or null if not specified
     */
    public SanitizationLevel getPreferredLevel() {
        return preferredLevel;
    }

    /**
     * Returns whether JWE encryption is enabled.
     *
     * @return true if encryption is enabled, false otherwise
     */
    public boolean isEncryptionEnabled() {
        return enableEncryption;
    }

    /**
     * Returns whether user confirmation is required.
     *
     * @return true if confirmation is required, false otherwise
     */
    public boolean isConfirmationRequired() {
        return requireConfirmation;
    }

    /**
     * Returns the effective sanitization level for this context.
     * <p>
     * If a preferred level is specified, it is returned. Otherwise,
     * returns the default level (MEDIUM) as per the system's security policy.
     * </p>
     *
     * @return the effective sanitization level
     */
    public SanitizationLevel getEffectiveLevel() {
        return preferredLevel != null ? preferredLevel : SanitizationLevel.MEDIUM;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProtectionContext that = (ProtectionContext) o;
        return enableEncryption == that.enableEncryption &&
               requireConfirmation == that.requireConfirmation &&
               originalPrompt.equals(that.originalPrompt) &&
               preferredLevel == that.preferredLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(originalPrompt, preferredLevel, 
                           enableEncryption, requireConfirmation);
    }

    @Override
    public String toString() {
        return "ProtectionContext{" +
               "preferredLevel=" + preferredLevel +
               ", enableEncryption=" + enableEncryption +
               ", requireConfirmation=" + requireConfirmation +
               ", promptLength=" + originalPrompt.length() +
               '}';
    }
}
