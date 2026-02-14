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
 * Represents the result of sensitive information detection and sanitization.
 * <p>
 * This class encapsulates all information about the sanitization process,
 * including whether sensitive information was detected, the details of each
 * detected sensitive item, the sanitized text, and the sanitization level applied.
 * </p>
 * <p>
 * This class is immutable and thread-safe, following Effective Java Item 15
 * and Item 17. It follows the Value Object pattern from Domain-Driven Design.
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Provides a complete audit trail of detected sensitive information</li>
 *   <li>Returns the highest severity level found for decision-making</li>
 *   <li>Contains the sanitized text ready for use</li>
 *   <li>Records the sanitization level applied for transparency</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
public class SanitizationResult {
    
    /**
     * Indicates whether any sensitive information was detected.
     */
    private final boolean hasSensitiveInfo;
    
    /**
     * List of all detected sensitive information items.
     * <p>
     * This list is sorted by the severity level (HIGH first) and then by
     * start index in the original prompt, ensuring consistent ordering for
     * display and processing.
     * </p>
     */
    private final List<SensitiveInfo> sensitiveInfos;
    
    /**
     * The sanitized prompt text.
     * <p>
     * If no sanitization was applied (level = NONE), this will be the same
     * as the original prompt. Otherwise, it contains the text with sensitive
     * information masked or replaced according to the sanitization level.
     * </p>
     */
    private final String sanitizedPrompt;
    
    /**
     * The sanitization level that was applied.
     */
    private final SanitizationLevel appliedLevel;

    /**
     * Constructs a new SanitizationResult instance.
     *
     * @param hasSensitiveInfo whether any sensitive information was detected
     * @param sensitiveInfos list of detected sensitive information items
     * @param sanitizedPrompt the sanitized prompt text
     * @param appliedLevel the sanitization level applied
     * @throws NullPointerException if sensitiveInfos, sanitizedPrompt, or appliedLevel is null
     */
    public SanitizationResult(boolean hasSensitiveInfo,
                              List<SensitiveInfo> sensitiveInfos,
                              String sanitizedPrompt,
                              SanitizationLevel appliedLevel) {
        this.hasSensitiveInfo = hasSensitiveInfo;
        this.sensitiveInfos = Objects.requireNonNull(sensitiveInfos, "SensitiveInfos cannot be null");
        this.sanitizedPrompt = Objects.requireNonNull(sanitizedPrompt, "Sanitized prompt cannot be null");
        this.appliedLevel = Objects.requireNonNull(appliedLevel, "Applied level cannot be null");
    }

    /**
     * Returns whether any sensitive information was detected.
     *
     * @return true if sensitive information was detected, false otherwise
     */
    public boolean hasSensitiveInfo() {
        return hasSensitiveInfo;
    }

    /**
     * Returns the list of detected sensitive information items.
     * <p>
     * The returned list is unmodifiable to maintain immutability.
     * </p>
     *
     * @return an unmodifiable list of sensitive information items
     */
    public List<SensitiveInfo> getSensitiveInfos() {
        return Collections.unmodifiableList(sensitiveInfos);
    }

    /**
     * Returns the sanitized prompt text.
     *
     * @return the sanitized prompt text
     */
    public String getSanitizedPrompt() {
        return sanitizedPrompt;
    }

    /**
     * Returns the sanitization level that was applied.
     *
     * @return the applied sanitization level
     */
    public SanitizationLevel getAppliedLevel() {
        return appliedLevel;
    }

    /**
     * Returns the highest severity level among all detected sensitive information.
     * <p>
     * This method is useful for determining the appropriate user interface
     * response and default handling strategy. If no sensitive information was
     * detected, returns {@link Severity#LOW}.
     * </p>
     *
     * @return the maximum severity level detected
     */
    public Severity getMaxSeverity() {
        return sensitiveInfos.stream()
                .map(SensitiveInfo::getSeverity)
                .max(Enum::compareTo)
                .orElse(Severity.LOW);
    }

    /**
     * Returns the count of detected sensitive information items.
     *
     * @return the number of sensitive information items detected
     */
    public int getSensitiveInfoCount() {
        return sensitiveInfos.size();
    }

    /**
     * Returns whether any HIGH severity sensitive information was detected.
     *
     * @return true if HIGH severity information was detected, false otherwise
     */
    public boolean hasHighSeverityInfo() {
        return sensitiveInfos.stream()
                .anyMatch(info -> info.getSeverity() == Severity.HIGH);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SanitizationResult that = (SanitizationResult) o;
        return hasSensitiveInfo == that.hasSensitiveInfo &&
               sensitiveInfos.equals(that.sensitiveInfos) &&
               sanitizedPrompt.equals(that.sanitizedPrompt) &&
               appliedLevel == that.appliedLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(hasSensitiveInfo, sensitiveInfos, sanitizedPrompt, appliedLevel);
    }

    @Override
    public String toString() {
        return "SanitizationResult{" +
               "hasSensitiveInfo=" + hasSensitiveInfo +
               ", sensitiveInfoCount=" + getSensitiveInfoCount() +
               ", maxSeverity=" + getMaxSeverity() +
               ", appliedLevel=" + appliedLevel +
               ", sanitizedPromptLength=" + sanitizedPrompt.length() +
               '}';
    }
}
