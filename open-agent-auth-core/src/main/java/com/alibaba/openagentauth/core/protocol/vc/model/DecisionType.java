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
 * Enumeration of user decision types for prompt protection.
 * <p>
 * This enum defines the possible decisions a user can make when presented
 * with sensitive information detected in their prompt. Each decision type
 * represents a different approach to handling the prompt before submission.
 * </p>
 * <p>
 * The decision types are designed to provide users with clear, actionable
 * choices that balance privacy protection with user control:
 * <ul>
 *   <li>SEND_ORIGINAL: Send the prompt without any modifications</li>
 *   <li>SEND_SANITIZED: Send the prompt with sensitive information masked</li>
 *   <li>CANCEL: Abort the operation entirely</li>
 *   <li>EDIT: Modify the prompt before making a final decision</li>
 * </ul>
 * </p>
 * <p>
 * This enum is immutable and thread-safe, following Effective Java Item 15.
 * </p>
 *
 * @since 1.0
 */
public enum DecisionType {
    
    /**
     * Send the original prompt without any modifications.
     * <p>
     * This decision indicates that the user has reviewed the detected
     * sensitive information and explicitly chosen to send the prompt
     * in its original form. This option should only be available when
     * no HIGH severity information is detected, or when the user
     * explicitly overrides the mandatory sanitization warning.
     * </p>
     * <p>
     * Warning: Using this option with sensitive information may expose
     * personal data to third parties. Users should be aware of the
     * privacy implications before choosing this option.
     * </p>
     */
    SEND_ORIGINAL,
    
    /**
     * Send the sanitized prompt with sensitive information masked.
     * <p>
     * This decision indicates that the user accepts the sanitization
     * suggestions and wants to send the prompt with sensitive information
     * masked according to the recommended sanitization level. This is
     * the recommended option for most use cases.
     * </p>
     * <p>
     * The sanitization level applied will be determined by the severity
     * of detected information and system configuration.
     * </p>
     */
    SEND_SANITIZED,
    
    /**
     * Cancel the operation entirely.
     * <p>
     * This decision indicates that the user wants to abort the current
     * operation without submitting the prompt. This option is useful when
     * the user decides not to proceed or wants to modify their approach.
     * </p>
     */
    CANCEL,
    
    /**
     * Edit the prompt before making a final decision.
     * <p>
     * This decision indicates that the user wants to modify the prompt
     * content to remove or rephrase sensitive information before
     * submission. After editing, the prompt will be re-evaluated for
     * sensitive information (dual detection mechanism).
     * </p>
     * <p>
     * This option supports the dual detection mechanism by allowing
     * users to modify the prompt and then having the system re-scan
     * for any newly introduced sensitive information.
     * </p>
     */
    EDIT;

    /**
     * Determines if this decision type results in prompt submission.
     *
     * @return true if this decision submits the prompt (original or sanitized)
     */
    public boolean isSubmission() {
        return this == SEND_ORIGINAL || this == SEND_SANITIZED;
    }

    /**
     * Determines if this decision type results in aborting the operation.
     *
     * @return true if this decision cancels the operation
     */
    public boolean isCancellation() {
        return this == CANCEL;
    }

    /**
     * Determines if this decision type allows prompt modification.
     *
     * @return true if this decision allows editing
     */
    public boolean allowsModification() {
        return this == EDIT;
    }
}
