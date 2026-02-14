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
 * Represents the result of a user's decision in the prompt protection process.
 * <p>
 * This class encapsulates the user's choice regarding how to handle detected
 * sensitive information in their prompt. It follows the Value Object pattern
 * from Domain-Driven Design, ensuring immutability and thread-safety.
 * </p>
 * <p>
 * The decision result includes:
 * <ul>
 *   <li>The type of decision made by the user</li>
 *   <li>The final prompt content after user modification (if applicable)</li>
 * </ul>
 * </p>
 * <p>
 * This class is immutable and thread-safe, following Effective Java Item 15
 * and Item 17.
 * </p>
 *
 * @since 1.0
 * @see DecisionType
 */
public class UserDecisionResult {
    
    /**
     * The type of decision made by the user.
     */
    private final DecisionType decisionType;
    
    /**
     * The final prompt content after user modification.
     * <p>
     * If the user chose to edit the prompt, this contains the modified version.
     * If the user chose to send original or sanitized, this contains the
     * corresponding prompt. If the user cancelled, this is null.
     * </p>
     */
    private final String finalPrompt;

    /**
     * Constructs a new UserDecisionResult for a submission decision.
     *
     * @param decisionType the type of decision (must be SEND_ORIGINAL or SEND_SANITIZED)
     * @param finalPrompt the final prompt content
     * @throws NullPointerException if decisionType or finalPrompt is null
     * @throws IllegalArgumentException if decisionType is not a submission type
     */
    public UserDecisionResult(DecisionType decisionType, String finalPrompt) {
        this.decisionType = Objects.requireNonNull(decisionType, "Decision type cannot be null");
        this.finalPrompt = Objects.requireNonNull(finalPrompt, "Final prompt cannot be null");
        
        if (!decisionType.isSubmission()) {
            throw new IllegalArgumentException("Decision type must be a submission type: " + decisionType);
        }
    }

    /**
     * Constructs a new UserDecisionResult for a cancellation.
     *
     * @param decisionType the type of decision (must be CANCEL or EDIT)
     * @throws NullPointerException if decisionType is null
     * @throws IllegalArgumentException if decisionType is CANCEL or EDIT
     */
    public UserDecisionResult(DecisionType decisionType) {
        this.decisionType = Objects.requireNonNull(decisionType, "Decision type cannot be null");
        this.finalPrompt = null;
        
        if (decisionType.isSubmission()) {
            throw new IllegalArgumentException(
                "Decision type must be CANCEL or EDIT: " + decisionType);
        }
    }

    /**
     * Returns the type of decision made by the user.
     *
     * @return the decision type
     */
    public DecisionType getDecisionType() {
        return decisionType;
    }

    /**
     * Returns the final prompt content after user modification.
     *
     * @return the final prompt, or null if the operation was cancelled
     */
    public String getFinalPrompt() {
        return finalPrompt;
    }

    /**
     * Returns whether this decision results in prompt submission.
     *
     * @return true if this decision submits the prompt
     */
    public boolean isSubmission() {
        return decisionType.isSubmission();
    }

    /**
     * Returns whether this decision cancels the operation.
     *
     * @return true if this decision cancels the operation
     */
    public boolean isCancellation() {
        return decisionType.isCancellation();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserDecisionResult that = (UserDecisionResult) o;
        return decisionType == that.decisionType && Objects.equals(finalPrompt, that.finalPrompt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(decisionType, finalPrompt);
    }

    @Override
    public String toString() {
        return "UserDecisionResult{" +
               "decisionType=" + decisionType +
               ", hasFinalPrompt=" + (finalPrompt != null) +
               '}';
    }
}
