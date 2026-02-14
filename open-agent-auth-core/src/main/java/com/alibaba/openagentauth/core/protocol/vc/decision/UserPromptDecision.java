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

import com.alibaba.openagentauth.core.protocol.vc.model.DecisionType;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionContext;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationResult;
import com.alibaba.openagentauth.core.protocol.vc.model.UserDecisionResult;

/**
 * Interface for managing user decisions in the prompt protection process.
 * <p>
 * This interface defines the contract for presenting prompt protection information
 * to users and collecting their decisions about how to handle detected sensitive
 * information. It implements the decoupled interface design using
 * {@code PromptPresentationInfo} DTO to isolate layers.
 * </p>
 * <p>
 * The user decision layer is the third line of defense in the three-layer
 * protection mechanism. It provides users with control over their data while
 * maintaining security through intelligent defaults and clear presentation.
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Decoupled interface design using PromptPresentationInfo DTO</li>
 *   <li>Support for multiple decision types (send original, send sanitized, cancel, edit)</li>
 *   <li>Intelligent default handling based on severity levels</li>
 *   <li>Dual detection mechanism support for re-scanning after edits</li>
 *   <li>Clear user interface with real-time feedback</li>
 * </ul>
 * </p>
 * <p>
 * This interface follows the Interface Segregation Principle from Clean
 * Architecture, focusing solely on user interaction and decision collection.
 * </p>
 *
 * @since 1.0
 */
public interface UserPromptDecision {
    
    /**
     * Presents the prompt protection information to the user.
     * <p>
     * This method creates a presentation DTO containing all information
     * needed to display the protection status to the user, including
     * detected sensitive information, sanitization preview, and
     * recommended actions.
     * </p>
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return the presentation information DTO
     */
    PromptPresentationInfo present(ProtectionContext context, SanitizationResult sanitizationResult);
    
    /**
     * Collects the user's decision about how to handle the prompt.
     * <p>
     * This method presents the options to the user and collects their
     * choice. The implementation may provide a UI, command-line interface,
     * or other interaction mechanism.
     * </p>
     *
     * @param presentationInfo the presentation information
     * @return the user's decision result
     */
    UserDecisionResult collectDecision(PromptPresentationInfo presentationInfo);
    
    /**
     * Processes a user decision and returns the final result.
     * <p>
     * This method is called after the user has made a decision about how to
     * handle the detected sensitive information. It creates a UserDecisionResult
     * object that encapsulates the decision and any modifications to the prompt.
     * </p>
     *
     * @param decisionType the type of decision
     * @param prompt the prompt content (may be modified if decision is EDIT)
     * @return the user decision result
     */
    UserDecisionResult processDecision(DecisionType decisionType, String prompt);
    
    /**
     * Determines if user interaction is required based on the context.
     * <p>
     * This method evaluates whether the user needs to be presented with
     * a decision screen based on the protection context and sanitization
     * results.
     * </p>
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return true if user interaction is required, false otherwise
     */
    boolean requiresUserInteraction(ProtectionContext context, SanitizationResult sanitizationResult);
    
    /**
     * Gets the recommended decision type based on severity and context.
     * <p>
     * This method provides intelligent default recommendations based on
     * the detected sensitive information severity and user preferences.
     * </p>
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return the recommended decision type
     */
    DecisionType getRecommendedDecision(ProtectionContext context, SanitizationResult sanitizationResult);
}
