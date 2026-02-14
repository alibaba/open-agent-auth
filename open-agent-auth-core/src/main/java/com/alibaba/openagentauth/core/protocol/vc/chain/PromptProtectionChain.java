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
package com.alibaba.openagentauth.core.protocol.vc.chain;

import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionContext;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionResult;
import com.alibaba.openagentauth.core.protocol.vc.model.UserDecisionResult;

/**
 * Interface for coordinating the three-layer prompt protection mechanism.
 * <p>
 * This interface defines the contract for orchestrating the complete prompt
 * protection process, which consists of three complementary layers:
 * <ol>
 *   <li><b>JWE Encryption Layer</b>: Cryptographic protection using RFC 7516</li>
 *   <li><b>Intelligent Sanitization Layer</b>: Content-level protection with dual detection</li>
 *   <li><b>User Decision Layer</b>: User control with intelligent defaults</li>
 * </ol>
 * </p>
 * <p>
 * The three layers work together to provide comprehensive protection:
 * <ul>
 *   <li>JWE encryption ensures confidentiality during transmission and storage</li>
 *   <li>Sanitization reduces exposure of sensitive information at the content level</li>
 *   <li>User decision provides control and transparency</li>
 * </ul>
 * </p>
 * <p>
 * This interface follows the Facade pattern from Gang of Four, providing a
 * simplified interface to the complex protection subsystem.
 * </p>
 *
 * @since 1.0
 */
public interface PromptProtectionChain {
    
    /**
     * Applies the complete three-layer protection mechanism to a prompt.
     * <p>
     * This method orchestrates the entire protection process:
     * <ol>
     *   <li>Validate the protection context</li>
     *   <li>Apply intelligent sanitization with initial detection</li>
     *   <li>Present information to user and collect decision</li>
     *   <li>Apply JWE encryption if enabled</li>
     *   <li>Return the complete protection result</li>
     * </ol>
     * </p>
     *
     * @param context the protection context containing the prompt and configuration
     * @return the protection result containing the protected prompt and metadata
     * @throws IllegalArgumentException if context is null
     */
    ProtectionResult protect(ProtectionContext context);
    
    /**
     * Applies protection with user pre-approval.
     * <p>
     * This method is useful when the user has already made a decision
     * (e.g., through a previous interaction) and wants to proceed directly
     * without re-presentation.
     * </p>
     *
     * @param context the protection context
     * @param userDecision the user's pre-approved decision
     * @return the protection result
     * @throws IllegalArgumentException if context or userDecision is null
     */
    ProtectionResult protectWithDecision(ProtectionContext context, UserDecisionResult userDecision);
    
    /**
     * Re-applies protection after user editing.
     * <p>
     * This method implements the dual detection mechanism by re-scanning
     * the edited prompt for any newly introduced sensitive information.
     * </p>
     *
     * @param context the protection context
     * @param editedPrompt the edited prompt content
     * @param previousResult the previous protection result for comparison
     * @return the protection result for the edited prompt
     * @throws IllegalArgumentException if context, editedPrompt, or previousResult is null
     */
    ProtectionResult reProtect(ProtectionContext context, String editedPrompt, ProtectionResult previousResult);
}
