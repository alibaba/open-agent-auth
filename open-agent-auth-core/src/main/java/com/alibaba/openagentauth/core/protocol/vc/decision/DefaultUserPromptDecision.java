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
import com.alibaba.openagentauth.core.protocol.vc.model.Severity;
import com.alibaba.openagentauth.core.protocol.vc.model.UserDecisionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of user prompt decision management.
 * <p>
 * This implementation provides user interaction capabilities for prompt protection,
 * following the decoupled interface design using {@code PromptPresentationInfo} DTO.
 * It implements intelligent default handling based on severity levels and provides
 * clear user interface options.
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Decoupled interface design using PromptPresentationInfo DTO</li>
 *   <li>Intelligent default recommendations based on severity</li>
 *   <li>Support for all decision types (send original, send sanitized, cancel, edit)</li>
 *   <li>Dual detection mechanism support for re-scanning after edits</li>
 *   <li>Thread-safe implementation following Effective Java Item 70</li>
 * </ul>
 * </p>
 * <p>
 * This class is designed to be thread-safe and can be safely shared across
 * multiple threads.
 * </p>
 *
 * @since 1.0
 * @see UserPromptDecision
 */
public class DefaultUserPromptDecision implements UserPromptDecision {
    
    private static final Logger logger = LoggerFactory.getLogger(DefaultUserPromptDecision.class);
    
    /**
     * Constructs a new DefaultUserPromptDecision instance.
     * <p>
     * This constructor performs necessary initialization. The implementation
     * is stateless and thread-safe, following Effective Java Item 70.
     * </p>
     */
    public DefaultUserPromptDecision() {
        logger.debug("DefaultUserPromptDecision initialized");
    }
    
    /**
     * Presents the prompt protection information to the user.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return the presentation information DTO
     */
    @Override
    public PromptPresentationInfo present(ProtectionContext context, 
                                         SanitizationResult sanitizationResult) {
        if (context == null) {
            throw new IllegalArgumentException("Protection context cannot be null");
        }
        if (sanitizationResult == null) {
            throw new IllegalArgumentException("Sanitization result cannot be null");
        }

        // Get sanitized preview at the effective level
        String sanitizedPreview = sanitizationResult.getSanitizedPrompt();
        
        // Determine if confirmation is required
        boolean requiresConfirmation = context.isConfirmationRequired() || 
            sanitizationResult.hasSensitiveInfo();
        
        return new PromptPresentationInfo(
            context.getOriginalPrompt(),
            sanitizedPreview,
            sanitizationResult,
            requiresConfirmation
        );
    }
    
    /**
     * Collects the user's decision about how to handle the prompt.
     * <p>
     * This is a placeholder implementation. In a real application, this would
     * present a UI or CLI interface to collect the user's choice. For now,
     * it returns a default decision based on the recommendation.
     * </p>
     *
     * @param presentationInfo the presentation information
     * @return the user's decision result
     */
    @Override
    public UserDecisionResult collectDecision(PromptPresentationInfo presentationInfo) {
        if (presentationInfo == null) {
            throw new IllegalArgumentException("Presentation info cannot be null");
        }
        
        logger.debug("Collecting user decision");
        
        // Get recommended decision
        DecisionType recommendedDecision = getRecommendedDecision(presentationInfo);
        
        // In a real implementation, this would present UI and collect user input
        // For now, use the recommended decision
        return processDecision(
            recommendedDecision,
            presentationInfo.getSanitizedPromptPreview()
        );
    }
    
    /**
     * Processes a user decision and returns the final result.
     *
     * @param decisionType the type of decision
     * @param prompt the prompt content (may be modified if decision is EDIT)
     * @return the user decision result
     */
    @Override
    public UserDecisionResult processDecision(DecisionType decisionType, String prompt) {
        if (decisionType == null) {
            throw new IllegalArgumentException("Decision type cannot be null");
        }
        
        logger.debug("Processing user decision: {}", decisionType);
        
        // Validate that prompt is provided for submission decisions
        if (prompt == null || prompt.isEmpty()) {
            throw new IllegalArgumentException("Prompt cannot be null or empty for submission decisions");
        }
        
        return new UserDecisionResult(decisionType, prompt);
    }
    
    /**
     * Determines if user interaction is required based on the context.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return true if user interaction is required, false otherwise
     */
    @Override
    public boolean requiresUserInteraction(ProtectionContext context, 
                                           SanitizationResult sanitizationResult) {
        if (context == null || sanitizationResult == null) {
            return false;
        }
        
        // Require interaction if:
        // 1. Context explicitly requires confirmation
        // 2. Sensitive information was detected
        // 3. HIGH severity information was detected (always require confirmation)
        
        if (context.isConfirmationRequired()) {
            return true;
        }
        
        if (sanitizationResult.hasSensitiveInfo()) {
            // HIGH severity always requires interaction
            if (sanitizationResult.hasHighSeverityInfo()) {
                logger.debug("User interaction required: HIGH severity info detected");
                return true;
            }
            
            // MEDIUM severity requires interaction unless user configured otherwise
            if (sanitizationResult.getMaxSeverity() == Severity.MEDIUM) {
                logger.debug("User interaction required: MEDIUM severity info detected");
                return true;
            }
            
            // LOW severity may not require interaction based on preferences
            logger.debug("User interaction optional: LOW severity info detected");
            return false;
        }
        
        return false;
    }
    
    /**
     * Gets the recommended decision type based on severity and context.
     *
     * @param context the protection context
     * @param sanitizationResult the sanitization result
     * @return the recommended decision type
     */
    @Override
    public DecisionType getRecommendedDecision(ProtectionContext context, 
                                               SanitizationResult sanitizationResult) {
        if (context == null || sanitizationResult == null) {
            return DecisionType.SEND_ORIGINAL;
        }
        
        if (!sanitizationResult.hasSensitiveInfo()) {
            // No sensitive info, recommend sending original
            return DecisionType.SEND_ORIGINAL;
        }
        
        Severity maxSeverity = sanitizationResult.getMaxSeverity();
        
        if (maxSeverity == Severity.HIGH) {
            // HIGH severity: recommend sending sanitized (mandatory)
            logger.debug("Recommending SEND_SANITIZED for HIGH severity");
            return DecisionType.SEND_SANITIZED;
        }
        
        if (maxSeverity == Severity.MEDIUM) {
            // MEDIUM severity: recommend sending sanitized
            logger.debug("Recommending SEND_SANITIZED for MEDIUM severity");
            return DecisionType.SEND_SANITIZED;
        }
        
        // LOW severity: recommend sending sanitized but allow override
        logger.debug("Recommending SEND_SANITIZED for LOW severity (override allowed)");
        return DecisionType.SEND_SANITIZED;
    }
    
    /**
     * Gets the recommended decision type based on presentation info.
     * <p>
     * This is a convenience method that extracts information from the
     * presentation info and delegates to the main getRecommendedDecision method.
     * </p>
     *
     * @param presentationInfo the presentation information
     * @return the recommended decision type
     */
    public DecisionType getRecommendedDecision(PromptPresentationInfo presentationInfo) {
        if (presentationInfo == null) {
            return DecisionType.SEND_ORIGINAL;
        }
        
        // Create a minimal context for decision making
        ProtectionContext context = new ProtectionContext(
            presentationInfo.getOriginalPrompt(),
            presentationInfo.getAppliedLevel(),
            false,  // Encryption not relevant for decision
            presentationInfo.isRequiresConfirmation()
        );
        
        // Create a sanitization result from the presentation info
        SanitizationResult result = new SanitizationResult(
            presentationInfo.hasSensitiveInfo(),
            presentationInfo.getSensitiveInfos(),
            presentationInfo.getSanitizedPromptPreview(),
            presentationInfo.getAppliedLevel()
        );
        
        return getRecommendedDecision(context, result);
    }
}
