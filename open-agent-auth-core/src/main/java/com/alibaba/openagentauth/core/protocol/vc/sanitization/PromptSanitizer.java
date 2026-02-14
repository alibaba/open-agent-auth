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
package com.alibaba.openagentauth.core.protocol.vc.sanitization;

import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationLevel;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationResult;

/**
 * Interface for prompt sanitization to detect and mask sensitive information.
 * <p>
 * This interface defines the contract for detecting sensitive information
 * in user prompts and applying appropriate sanitization strategies. It implements
 * the dual detection mechanism:
 * <ol>
 *   <li>Initial pre-sanitization detection when the prompt is first submitted</li>
 *   <li>Real-time re-detection after user editing</li>
 * </ol>
 * </p>
 * <p>
 * The sanitization layer is the second line of defense in the three-layer
 * protection mechanism. It operates independently of encryption and user
 * decision layers, providing content-level protection by identifying and
 * masking sensitive information.
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Supports multiple sensitive information types (phone, email, ID card, etc.)</li>
 *   <li>Configurable sanitization levels (NONE, LOW, MEDIUM, HIGH)</li>
 *   <li>Dual detection mechanism for comprehensive protection</li>
 *   <li>Pattern-based detection using regular expressions</li>
 *   <li>Severity-based default handling</li>
 * </ul>
 * </p>
 * <p>
 * This interface follows the Interface Segregation Principle from Clean
 * Architecture, focusing solely on detection and sanitization operations.
 * </p>
 *
 * @since 1.0
 */
public interface PromptSanitizer {
    
    /**
     * Detects sensitive information in the prompt and applies sanitization.
     * <p>
     * This is the primary method for prompt sanitization. It performs the
     * initial detection and applies the specified sanitization level.
     * </p>
     *
     * @param prompt the prompt text to sanitize
     * @param level the sanitization level to apply
     * @return the sanitization result containing detected information and sanitized text
     * @throws IllegalArgumentException if prompt is null or level is null
     */
    SanitizationResult sanitize(String prompt, SanitizationLevel level);
    
    /**
     * Re-detects sensitive information after user editing.
     * <p>
     * This method implements the second part of the dual detection mechanism.
     * When a user edits their prompt, this method re-scans for any newly
     * introduced sensitive information that might have been added during editing.
     * </p>
     * <p>
     * This is critical for security because users might inadvertently add
     * sensitive information while trying to remove or rephrase existing content.
     * </p>
     *
     * @param editedPrompt the edited prompt text
     * @param previousResult the previous sanitization result for comparison
     * @param level the sanitization level to apply
     * @return the sanitization result with newly detected information
     * @throws IllegalArgumentException if editedPrompt or level is null
     */
    SanitizationResult reDetect(String editedPrompt, SanitizationResult previousResult, SanitizationLevel level);
}
