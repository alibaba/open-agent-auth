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

import com.alibaba.openagentauth.core.protocol.vc.decision.DefaultUserPromptDecision;
import com.alibaba.openagentauth.core.protocol.vc.decision.PromptPresentationInfo;
import com.alibaba.openagentauth.core.protocol.vc.decision.UserPromptDecision;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptEncryptionService;
import com.alibaba.openagentauth.core.protocol.vc.model.DecisionType;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionContext;
import com.alibaba.openagentauth.core.protocol.vc.model.ProtectionResult;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationLevel;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationResult;
import com.alibaba.openagentauth.core.protocol.vc.model.UserDecisionResult;
import com.alibaba.openagentauth.core.protocol.vc.sanitization.DefaultPromptSanitizer;
import com.alibaba.openagentauth.core.protocol.vc.sanitization.PromptSanitizer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of the three-layer prompt protection chain coordinator.
 * <p>
 * This implementation orchestrates the complete prompt protection process,
 * coordinating the three complementary protection layers:
 * <ol>
 *   <li><b>JWE Encryption Layer</b>: Cryptographic protection using RFC 7516</li>
 *   <li><b>Intelligent Sanitization Layer</b>: Content-level protection with dual detection</li>
 *   <li><b>User Decision Layer</b>: User control with intelligent defaults</li>
 * </ol>
 * </p>
 * <p>
 * The protection flow:
 * <ol>
 *   <li>Validate the protection context</li>
 *   <li>Apply intelligent sanitization with initial detection</li>
 *   <li>Determine if user interaction is required</li>
 *   <li>Present information to user and collect decision (if required)</li>
 *   <li>Apply JWE encryption if enabled</li>
 *   <li>Return the complete protection result</li>
 * </ol>
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Orchestrates three complementary protection layers</li>
 *   <li>Implements dual detection mechanism for comprehensive protection</li>
 *   <li>Supports user pre-approval for faster processing</li>
 *   <li>Thread-safe implementation following Effective Java Item 70</li>
 *   <li>Comprehensive error handling and logging</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 * @see PromptProtectionChain
 */
public class DefaultPromptProtectionChain implements PromptProtectionChain {
    
    private static final Logger logger = LoggerFactory.getLogger(DefaultPromptProtectionChain.class);
    
    /**
     * The JWE encryption protection layer.
     */
    private final PromptEncryptionService promptEncryptionService;
    
    /**
     * The prompt sanitization layer.
     */
    private final PromptSanitizer sanitizer;
    
    /**
     * The user decision layer.
     */
    private final UserPromptDecision userDecision;
    
    /**
     * Constructs a new DefaultPromptProtectionChain with custom implementations.
     * <p>
     * This constructor allows dependency injection of custom implementations
     * for testing and flexibility.
     * </p>
     *
     * @param promptEncryptionService the prompt encryption service
     * @param sanitizer the sanitization implementation
     * @param userDecision the user decision implementation
     */
    public DefaultPromptProtectionChain(PromptEncryptionService promptEncryptionService,
                                        PromptSanitizer sanitizer,
                                        UserPromptDecision userDecision) {
        this.promptEncryptionService = promptEncryptionService;
        this.sanitizer = sanitizer != null ? sanitizer : new DefaultPromptSanitizer();
        this.userDecision = userDecision != null ? userDecision : new DefaultUserPromptDecision();
        
        logger.debug("DefaultPromptProtectionChain initialized with custom implementations");
    }
    
    /**
     * Applies the complete three-layer protection mechanism to a prompt.
     *
     * @param context the protection context containing the prompt and configuration
     * @return the protection result containing the protected prompt and metadata
     * @throws IllegalArgumentException if context is null
     */
    @Override
    public ProtectionResult protect(ProtectionContext context) {

        logger.info("Starting prompt protection");
        validateContext(context);

        // Step 1: Apply intelligent sanitization with initial detection
        SanitizationResult sanitizationResult = performSanitization(context);

        // Step 2: Collect user decision based on sanitization result
        UserDecisionResult userDecisionResult = collectUserDecision(context, sanitizationResult, false);

        // Check if user cancelled
        if (userDecisionResult.isCancellation()) {
            logger.info("User cancelled the operation");
            return new ProtectionResult("User cancelled the operation");
        }

        // Step 3: Apply JWE encryption if enabled and return result
        ProtectionResult result = finalizeProtection(context, sanitizationResult, userDecisionResult);

        logger.info("Prompt protection complete: success={}, encrypted={}, hasSensitiveInfo={}",
            result.isSuccess(), result.isEncrypted(), result.hasSensitiveInfo());

        return result;
    }

    /**
     * Applies protection with user pre-approval.
     *
     * @param context      the protection context
     * @param userDecision the user's pre-approved decision
     * @return the protection result
     * @throws IllegalArgumentException if context or userDecision is null
     */
    @Override
    public ProtectionResult protectWithDecision(ProtectionContext context, UserDecisionResult userDecision) {

        logger.info("Starting prompt protection with pre-approved decision");
        validateContext(context);
        validateUserDecision(userDecision);

        // Step 1: Apply sanitization
        SanitizationResult sanitizationResult = performSanitization(context);

        logger.debug("Sanitization complete: {} items detected",
            sanitizationResult.getSensitiveInfoCount());

        // Step 2: Check if pre-approved decision is cancellation
        if (userDecision.isCancellation()) {
            logger.info("Pre-approved decision is cancellation");
            return new ProtectionResult("User cancelled the operation");
        }

        // Step 3: Apply JWE encryption if enabled and return result
        ProtectionResult result = finalizeProtection(context, sanitizationResult, userDecision);

        logger.info("Prompt protection with decision complete: success={}, encrypted={}",
            result.isSuccess(), result.isEncrypted());

        return result;
    }
    
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
    @Override
    public ProtectionResult reProtect(ProtectionContext context, String editedPrompt, ProtectionResult previousResult) {

        logger.info("Re-applying protection after user editing");
        validateContext(context);
        validateEditedPrompt(editedPrompt);
        validatePreviousResult(previousResult);

        // Step 1: Re-detect sensitive information with dual detection mechanism
        SanitizationResult newSanitizationResult = performReDetection(context, editedPrompt, previousResult);

        // Step 2: Collect user decision based on re-detection result
        UserDecisionResult userDecisionResult = collectUserDecision(context, newSanitizationResult, true);

        // Check if user cancelled
        if (userDecisionResult.isCancellation()) {
            logger.info("User cancelled the operation after editing");
            return new ProtectionResult("User cancelled the operation");
        }

        // Step 3: Apply JWE encryption if enabled and return result
        ProtectionResult result = finalizeProtection(context, newSanitizationResult, userDecisionResult);

        logger.info("Prompt re-protection complete: success={}, encrypted={}, hasSensitiveInfo={}",
            result.isSuccess(), result.isEncrypted(), result.hasSensitiveInfo());

        return result;
    }

    /**
     * Validates the protection context.
     *
     * @param context the protection context to validate
     * @throws IllegalArgumentException if context is null
     */
    private void validateContext(ProtectionContext context) {
        if (context == null) {
            throw new IllegalArgumentException("Protection context cannot be null");
        }
    }
    
    /**
     * Validates the user decision.
     *
     * @param userDecision the user decision to validate
     * @throws IllegalArgumentException if userDecision is null
     */
    private void validateUserDecision(UserDecisionResult userDecision) {
        if (userDecision == null) {
            throw new IllegalArgumentException("User decision cannot be null");
        }
    }
    
    /**
     * Validates the edited prompt.
     *
     * @param editedPrompt the edited prompt to validate
     * @throws IllegalArgumentException if editedPrompt is null or empty
     */
    private void validateEditedPrompt(String editedPrompt) {
        if (editedPrompt == null || editedPrompt.isEmpty()) {
            throw new IllegalArgumentException("Edited prompt cannot be null or empty");
        }
    }
    
    /**
     * Validates the previous protection result.
     *
     * @param previousResult the previous protection result to validate
     * @throws IllegalArgumentException if previousResult is null
     */
    private void validatePreviousResult(ProtectionResult previousResult) {
        if (previousResult == null) {
            throw new IllegalArgumentException("Previous protection result cannot be null");
        }
    }
    
    /**
     * Performs sanitization on the prompt.
     *
     * @param context the protection context
     * @return the sanitization result
     */
    private SanitizationResult performSanitization(ProtectionContext context) {

        SanitizationLevel effectiveLevel = context.getEffectiveLevel();
        SanitizationResult sanitizationResult = sanitizer.sanitize(context.getOriginalPrompt(), effectiveLevel);
        
        logger.debug("Sanitization complete: {} items detected, level: {}", 
                    sanitizationResult.getSensitiveInfoCount(), effectiveLevel);
        
        return sanitizationResult;
    }
    
    /**
     * Performs re-detection on the edited prompt.
     *
     * @param context the protection context
     * @param editedPrompt the edited prompt content
     * @param previousResult the previous protection result for comparison
     * @return the sanitization result with re-detected information
     */
    private SanitizationResult performReDetection(ProtectionContext context, String editedPrompt,
                                                   ProtectionResult previousResult) {
        SanitizationLevel effectiveLevel = context.getEffectiveLevel();
        SanitizationResult newSanitizationResult = sanitizer.reDetect(
            editedPrompt,
            previousResult.getSanitizationResult(),
            effectiveLevel
        );
        
        logger.debug("Re-detection complete: {} items detected", 
                    newSanitizationResult.getSensitiveInfoCount());
        
        return newSanitizationResult;
    }
    
    /**
     * Collects user decision based on sanitization result.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @param isReDetection whether this is a re-detection scenario
     * @return the user decision result
     */
    private UserDecisionResult collectUserDecision(ProtectionContext context, 
                                                   SanitizationResult sanitizationResult,
                                                   boolean isReDetection) {
        boolean requiresInteraction = userDecision.requiresUserInteraction(context, sanitizationResult);
        
        if (requiresInteraction) {
            return collectInteractiveDecision(context, sanitizationResult, isReDetection);
        } else {
            return collectAutomaticDecision(context, sanitizationResult);
        }
    }
    
    /**
     * Collects user decision through interactive presentation.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @param isReDetection whether this is a re-detection scenario
     * @return the user decision result
     */
    private UserDecisionResult collectInteractiveDecision(ProtectionContext context,
                                                          SanitizationResult sanitizationResult,
                                                          boolean isReDetection) {
        if (isReDetection) {
            logger.debug("New sensitive info detected, presenting updated information");
        } else {
            logger.debug("User interaction required, presenting information");
        }
        
        PromptPresentationInfo presentationInfo = userDecision.present(context, sanitizationResult);
        UserDecisionResult userDecisionResult = userDecision.collectDecision(presentationInfo);
        
        logger.debug("User decision collected: {}", userDecisionResult.getDecisionType());
        
        return userDecisionResult;
    }
    
    /**
     * Collects user decision automatically without interaction.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return the user decision result
     */
    private UserDecisionResult collectAutomaticDecision(ProtectionContext context,
                                                        SanitizationResult sanitizationResult) {
        logger.debug("No user interaction required, using recommended decision");
        
        DecisionType recommendedDecision = userDecision.getRecommendedDecision(context, sanitizationResult);
        
        return userDecision.processDecision(
            recommendedDecision,
            sanitizationResult.getSanitizedPrompt()
        );
    }
    
    /**
     * Finalizes protection by applying JWE encryption if enabled.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @param userDecisionResult the user decision result
     * @return the final protection result
     */
    private ProtectionResult finalizeProtection(ProtectionContext context,
                                               SanitizationResult sanitizationResult,
                                               UserDecisionResult userDecisionResult) {
        String finalPrompt = userDecisionResult.getFinalPrompt();
        String protectedPrompt;
        boolean encrypted = false;
        
        if (context.isEncryptionEnabled()) {
            protectedPrompt = applyJweEncryption(finalPrompt);
            encrypted = true;
        } else {
            protectedPrompt = finalPrompt;
        }
        
        return new ProtectionResult(
            protectedPrompt,
            sanitizationResult,
            userDecisionResult,
            encrypted
        );
    }
    
    /**
     * Applies JWE encryption to the prompt.
     *
     * @param prompt the prompt to encrypt
     * @return the encrypted prompt
     */
    private String applyJweEncryption(String prompt) {
        logger.debug("Applying JWE encryption");

        if (promptEncryptionService == null) {
            throw new IllegalArgumentException("PromptEncryptionService is not configured");
        }

        String encryptedPrompt = promptEncryptionService.encryptPrompt(prompt);

        logger.debug("JWE encryption complete");
        return encryptedPrompt;
    }

}
