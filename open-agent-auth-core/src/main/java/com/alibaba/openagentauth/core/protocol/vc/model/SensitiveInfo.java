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
 * Represents a detected sensitive information instance within a prompt.
 * <p>
 * This class encapsulates all metadata about a piece of sensitive information
 * that has been identified by the prompt sanitization mechanism. It follows
 * the Value Object pattern from Domain-Driven Design, ensuring immutability
 * and thread-safety.
 * </p>
 * <p>
 * Each instance contains:
 * <ul>
 *   <li>The type of sensitive information detected</li>
 *   <li>The actual sensitive value (for audit purposes)</li>
 *   <li>The severity level of the information</li>
 *   <li>The position of the information within the original text</li>
 * </ul>
 * </p>
 * <p>
 * This class is immutable and thread-safe, following Effective Java Item 15
 * and Item 17.
 * </p>
 *
 * @since 1.0
 * @see SensitiveInfoType
 * @see Severity
 */
public class SensitiveInfo {
    
    /**
     * The type of sensitive information detected.
     */
    private final SensitiveInfoType type;
    
    /**
     * The actual sensitive value extracted from the prompt.
     * <p>
     * This field stores the raw sensitive value for audit and logging purposes.
     * It should be handled with extreme care and never logged in plain text
     * in production environments.
     * </p>
     */
    private final String value;
    
    /**
     * The severity level of this sensitive information.
     */
    private final Severity severity;
    
    /**
     * The starting index of this sensitive information in the original prompt.
     * <p>
     * This zero-based index marks the position where the sensitive information
     * begins within the original text string.
     * </p>
     */
    private final int startIndex;
    
    /**
     * The ending index (exclusive) of this sensitive information in the original prompt.
     * <p>
     * This zero-based index marks the position after the last character of the
     * sensitive information within the original text string. The substring can
     * be extracted as originalPrompt.substring(startIndex, endIndex).
     * </p>
     */
    private final int endIndex;

    /**
     * Constructs a new SensitiveInfo instance with the specified properties.
     *
     * @param type the type of sensitive information detected
     * @param value the actual sensitive value
     * @param severity the severity level of the information
     * @param startIndex the starting index in the original prompt
     * @param endIndex the ending index (exclusive) in the original prompt
     * @throws NullPointerException if type, value, or severity is null
     * @throws IllegalArgumentException if startIndex or endIndex is negative,
     *                                  or if startIndex >= endIndex
     */
    public SensitiveInfo(SensitiveInfoType type, String value, Severity severity, 
                        int startIndex, int endIndex) {
        this.type = Objects.requireNonNull(type, "SensitiveInfoType cannot be null");
        this.value = Objects.requireNonNull(value, "Sensitive value cannot be null");
        this.severity = Objects.requireNonNull(severity, "Severity cannot be null");
        
        if (startIndex < 0) {
            throw new IllegalArgumentException("startIndex cannot be negative: " + startIndex);
        }
        if (endIndex < 0) {
            throw new IllegalArgumentException("endIndex cannot be negative: " + endIndex);
        }
        if (startIndex >= endIndex) {
            throw new IllegalArgumentException(
                "startIndex must be less than endIndex: startIndex=" + startIndex + ", endIndex=" + endIndex);
        }
        
        this.startIndex = startIndex;
        this.endIndex = endIndex;
    }

    /**
     * Returns the type of sensitive information detected.
     *
     * @return the sensitive information type
     */
    public SensitiveInfoType getType() {
        return type;
    }

    /**
     * Returns the actual sensitive value.
     * <p>
     * Warning: This method returns the raw sensitive value. Handle with extreme
     * care and never log this value in plain text in production environments.
     * </p>
     *
     * @return the sensitive value
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns the severity level of this sensitive information.
     *
     * @return the severity level
     */
    public Severity getSeverity() {
        return severity;
    }

    /**
     * Returns the starting index of this sensitive information in the original prompt.
     *
     * @return the starting index (zero-based)
     */
    public int getStartIndex() {
        return startIndex;
    }

    /**
     * Returns the ending index (exclusive) of this sensitive information in the original prompt.
     *
     * @return the ending index (zero-based, exclusive)
     */
    public int getEndIndex() {
        return endIndex;
    }

    /**
     * Returns the length of this sensitive information.
     *
     * @return the length in characters
     */
    public int getLength() {
        return endIndex - startIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SensitiveInfo that = (SensitiveInfo) o;
        return startIndex == that.startIndex &&
               endIndex == that.endIndex &&
               type == that.type &&
               severity == that.severity &&
               value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, value, severity, startIndex, endIndex);
    }

    @Override
    public String toString() {
        return "SensitiveInfo{" +
               "type=" + type +
               ", value='[REDACTED]'" +
               ", severity=" + severity +
               ", startIndex=" + startIndex +
               ", endIndex=" + endIndex +
               ", length=" + getLength() +
               '}';
    }
}
