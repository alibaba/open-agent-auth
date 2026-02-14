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

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents the final result of the prompt protection process.
 * <p>
 * This class encapsulates the complete outcome of applying the three-layer
 * protection mechanism (JWE encryption, intelligent sanitization, and user
 * decision) to a user prompt. It contains all information needed for
 * downstream processing and audit logging.
 * </p>
 * <p>
 * This class is immutable and thread-safe, following Effective Java Item 15
 * and Item 17. It follows the Value Object pattern from Domain-Driven Design.
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Contains the final protected prompt (possibly encrypted)</li>
 *   <li>Records all applied protection layers</li>
 *   <li>Provides a complete audit trail</li>
 *   <li>Indicates whether the operation was successful</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
public class ProtectionResult {
    
    /**
     * Indicates whether the protection process completed successfully.
     */
    private final boolean success;
    
    /**
     * The final protected prompt text.
     * <p>
     * If JWE encryption was applied, this will be the JWE encrypted string.
     * Otherwise, it will be the sanitized prompt text (or original if no
     * sanitization was applied).
     * </p>
     */
    private final String protectedPrompt;
    
    /**
     * The sanitization result, if sanitization was applied.
     * <p>
     * This field is null if no sanitization was performed (e.g., when the
     * user chose to send the original prompt without sanitization).
     * </p>
     */
    private final SanitizationResult sanitizationResult;
    
    /**
     * The user's decision, if user interaction was required.
     * <p>
     * This field is null if no user interaction was required (e.g., when
     * no sensitive information was detected and confirmation was not required).
     * </p>
     */
    private final UserDecisionResult userDecision;
    
    /**
     * Flag indicating whether JWE encryption was applied.
     */
    private final boolean encrypted;
    
    /**
     * Error message if the protection process failed.
     * <p>
     * This field is null if the protection process succeeded.
     * </p>
     */
    private final String errorMessage;

    /**
     * Constructs a successful ProtectionResult.
     *
     * @param protectedPrompt the final protected prompt
     * @param sanitizationResult the sanitization result (may be null)
     * @param userDecision the user's decision (may be null)
     * @param encrypted whether JWE encryption was applied
     * @throws NullPointerException if protectedPrompt is null
     */
    public ProtectionResult(String protectedPrompt,
                           SanitizationResult sanitizationResult,
                           UserDecisionResult userDecision,
                           boolean encrypted) {
        this.protectedPrompt = Objects.requireNonNull(protectedPrompt, "Protected prompt cannot be null");
        this.sanitizationResult = sanitizationResult;
        this.userDecision = userDecision;
        this.encrypted = encrypted;
        this.success = true;
        this.errorMessage = null;
    }

    /**
     * Constructs a failed ProtectionResult.
     *
     * @param errorMessage the error message describing the failure
     * @throws NullPointerException if errorMessage is null
     */
    public ProtectionResult(String errorMessage) {
        this.errorMessage = Objects.requireNonNull(errorMessage, "Error message cannot be null");
        this.success = false;
        this.protectedPrompt = null;
        this.sanitizationResult = null;
        this.userDecision = null;
        this.encrypted = false;
    }

    /**
     * Returns whether the protection process completed successfully.
     *
     * @return true if successful, false otherwise
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Returns the final protected prompt text.
     *
     * @return the protected prompt, or null if protection failed
     */
    public String getProtectedPrompt() {
        return protectedPrompt;
    }

    /**
     * Returns the sanitization result.
     *
     * @return the sanitization result, or null if no sanitization was applied
     */
    public SanitizationResult getSanitizationResult() {
        return sanitizationResult;
    }

    /**
     * Returns the user's decision.
     *
     * @return the user's decision, or null if no user interaction was required
     */
    public UserDecisionResult getUserDecision() {
        return userDecision;
    }

    /**
     * Returns whether JWE encryption was applied.
     *
     * @return true if encrypted, false otherwise
     */
    public boolean isEncrypted() {
        return encrypted;
    }

    /**
     * Returns the error message if the protection process failed.
     *
     * @return the error message, or null if protection succeeded
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Returns whether any sensitive information was detected.
     *
     * @return true if sensitive information was detected, false otherwise
     */
    public boolean hasSensitiveInfo() {
        return sanitizationResult != null && sanitizationResult.hasSensitiveInfo();
    }

    /**
     * Returns the list of detected sensitive information.
     *
     * @return an unmodifiable list of sensitive information items
     */
    public List<SensitiveInfo> getSensitiveInfos() {
        if (sanitizationResult == null) {
            return Collections.emptyList();
        }
        return sanitizationResult.getSensitiveInfos();
    }

    /**
     * Returns the maximum severity level of detected sensitive information.
     *
     * @return the maximum severity level, or null if no sensitive information was detected
     */
    public Severity getMaxSeverity() {
        if (sanitizationResult == null || !sanitizationResult.hasSensitiveInfo()) {
            return null;
        }
        return sanitizationResult.getMaxSeverity();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProtectionResult that = (ProtectionResult) o;
        return success == that.success &&
               encrypted == that.encrypted &&
               protectedPrompt.equals(that.protectedPrompt) &&
               Objects.equals(sanitizationResult, that.sanitizationResult) &&
               Objects.equals(userDecision, that.userDecision) &&
               Objects.equals(errorMessage, that.errorMessage);
    }

    @Override
    public int hashCode() {
        return Objects.hash(success, protectedPrompt, sanitizationResult, 
                           userDecision, encrypted, errorMessage);
    }

    @Override
    public String toString() {
        if (!success) {
            return "ProtectionResult{success=false, error='" + errorMessage + "'}";
        }
        return "ProtectionResult{" +
               "success=true" +
               ", encrypted=" + encrypted +
               ", hasSensitiveInfo=" + hasSensitiveInfo() +
               ", maxSeverity=" + getMaxSeverity() +
               ", protectedPromptLength=" + protectedPrompt.length() +
               '}';
    }
}
