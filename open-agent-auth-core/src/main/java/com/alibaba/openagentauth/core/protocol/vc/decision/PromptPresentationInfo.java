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
package com.alibaba.openagentauth.core.protocol.vc.decision;

import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationLevel;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationResult;
import com.alibaba.openagentauth.core.protocol.vc.model.Severity;
import com.alibaba.openagentauth.core.protocol.vc.model.SensitiveInfo;

import java.util.List;
import java.util.Objects;

/**
 * Data Transfer Object (DTO) for presenting prompt protection information to users.
 * <p>
 * This class encapsulates all information needed to display the protection status
 * to users in a decoupled manner. It follows the Data Transfer Object pattern from
 * Domain-Driven Design, ensuring clean separation between the decision layer and
 * presentation layer.
 * </p>
 * <p>
 * This DTO provides:
 * <ul>
 *   <li>Original prompt content for review</li>
 *   <li>Detected sensitive information with details</li>
 *   <li>Sanitized prompt preview</li>
 *   <li>Recommended actions based on severity</li>
 *   <li>Available options for user choice</li>
 * </ul>
 * </p>
 * <p>
 * This class is immutable and thread-safe, following Effective Java Item 15.
 * </p>
 *
 * @since 1.0
 */
public class PromptPresentationInfo {
    
    /**
     * The original prompt content.
     */
    private final String originalPrompt;
    
    /**
     * The sanitized prompt preview.
     */
    private final String sanitizedPromptPreview;
    
    /**
     * List of detected sensitive information items.
     */
    private final List<SensitiveInfo> sensitiveInfos;
    
    /**
     * The maximum severity level detected.
     */
    private final Severity maxSeverity;
    
    /**
     * The sanitization level applied for the preview.
     */
    private final SanitizationLevel appliedLevel;
    
    /**
     * Flag indicating whether user confirmation is required.
     */
    private final boolean requiresConfirmation;
    
    /**
     * Flag indicating whether any HIGH severity information was detected.
     */
    private final boolean hasHighSeverityInfo;
    
    /**
     * The count of detected sensitive information items.
     */
    private final int sensitiveInfoCount;

    /**
     * Constructs a new PromptPresentationInfo instance.
     *
     * @param originalPrompt the original prompt content
     * @param sanitizedPromptPreview the sanitized prompt preview
     * @param sanitizationResult the sanitization result
     * @param requiresConfirmation whether user confirmation is required
     * @throws NullPointerException if originalPrompt, sanitizedPromptPreview, or sanitizationResult is null
     */
    public PromptPresentationInfo(String originalPrompt, 
                                  String sanitizedPromptPreview,
                                  SanitizationResult sanitizationResult,
                                  boolean requiresConfirmation) {
        this.originalPrompt = Objects.requireNonNull(originalPrompt, "Original prompt cannot be null");
        this.sanitizedPromptPreview = Objects.requireNonNull(sanitizedPromptPreview, 
            "Sanitized prompt preview cannot be null");
        this.sensitiveInfos = Objects.requireNonNull(sanitizationResult, 
            "Sanitization result cannot be null").getSensitiveInfos();
        this.maxSeverity = sanitizationResult.getMaxSeverity();
        this.appliedLevel = sanitizationResult.getAppliedLevel();
        this.requiresConfirmation = requiresConfirmation;
        this.hasHighSeverityInfo = sanitizationResult.hasHighSeverityInfo();
        this.sensitiveInfoCount = sanitizationResult.getSensitiveInfoCount();
    }

    /**
     * Returns the original prompt content.
     *
     * @return the original prompt
     */
    public String getOriginalPrompt() {
        return originalPrompt;
    }

    /**
     * Returns the sanitized prompt preview.
     *
     * @return the sanitized prompt preview
     */
    public String getSanitizedPromptPreview() {
        return sanitizedPromptPreview;
    }

    /**
     * Returns the list of detected sensitive information items.
     *
     * @return an unmodifiable list of sensitive information items
     */
    public List<SensitiveInfo> getSensitiveInfos() {
        return java.util.Collections.unmodifiableList(sensitiveInfos);
    }

    /**
     * Returns the maximum severity level detected.
     *
     * @return the maximum severity level
     */
    public Severity getMaxSeverity() {
        return maxSeverity;
    }

    /**
     * Returns the sanitization level applied for the preview.
     *
     * @return the applied sanitization level
     */
    public SanitizationLevel getAppliedLevel() {
        return appliedLevel;
    }

    /**
     * Returns whether user confirmation is required.
     *
     * @return true if confirmation is required, false otherwise
     */
    public boolean isRequiresConfirmation() {
        return requiresConfirmation;
    }

    /**
     * Returns whether any HIGH severity information was detected.
     *
     * @return true if HIGH severity information was detected, false otherwise
     */
    public boolean hasHighSeverityInfo() {
        return hasHighSeverityInfo;
    }

    /**
     * Returns the count of detected sensitive information items.
     *
     * @return the number of sensitive information items detected
     */
    public int getSensitiveInfoCount() {
        return sensitiveInfoCount;
    }

    /**
     * Returns whether any sensitive information was detected.
     *
     * @return true if sensitive information was detected, false otherwise
     */
    public boolean hasSensitiveInfo() {
        return sensitiveInfoCount > 0;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PromptPresentationInfo that = (PromptPresentationInfo) o;
        return requiresConfirmation == that.requiresConfirmation &&
               hasHighSeverityInfo == that.hasHighSeverityInfo &&
               sensitiveInfoCount == that.sensitiveInfoCount &&
               originalPrompt.equals(that.originalPrompt) &&
               sanitizedPromptPreview.equals(that.sanitizedPromptPreview) &&
               sensitiveInfos.equals(that.sensitiveInfos) &&
               maxSeverity == that.maxSeverity &&
               appliedLevel == that.appliedLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(originalPrompt, sanitizedPromptPreview, sensitiveInfos, 
                           maxSeverity, appliedLevel, requiresConfirmation, 
                           hasHighSeverityInfo, sensitiveInfoCount);
    }

    @Override
    public String toString() {
        return "PromptPresentationInfo{" +
               "sensitiveInfoCount=" + sensitiveInfoCount +
               ", maxSeverity=" + maxSeverity +
               ", appliedLevel=" + appliedLevel +
               ", hasHighSeverityInfo=" + hasHighSeverityInfo +
               ", requiresConfirmation=" + requiresConfirmation +
               ", originalPromptLength=" + originalPrompt.length() +
               ", sanitizedPreviewLength=" + sanitizedPromptPreview.length() +
               '}';
    }
}
