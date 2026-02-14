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
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationLevel;
import com.alibaba.openagentauth.core.protocol.vc.model.SanitizationResult;
import com.alibaba.openagentauth.core.protocol.vc.model.Severity;
import com.alibaba.openagentauth.core.protocol.vc.model.SensitiveInfo;
import com.alibaba.openagentauth.core.protocol.vc.model.SensitiveInfoType;
import com.alibaba.openagentauth.core.protocol.vc.model.UserDecisionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DefaultUserPromptDecision}.
 * <p>
 * These tests validate the user prompt decision management functionality:
 * </p>
 * <ul>
 *   <li>Presentation of prompt protection information to users</li>
 *   <li>Collection and processing of user decisions</li>
 *   <li>Determination of when user interaction is required</li>
 *   <li>Recommendation of appropriate decision types based on severity</li>
 *   <li>Proper handling of all decision types (send original, send sanitized, cancel, edit)</li>
 * </ul>
 *
 * @see DefaultUserPromptDecision
 */
class DefaultUserPromptDecisionTest {

    private static final String TEST_PROMPT = "My phone is 13812345678, please call me.";
    private DefaultUserPromptDecision decision;

    @BeforeEach
    void setUp() {
        decision = new DefaultUserPromptDecision();
    }

    @Test
    void testPresentWithNullContext() {
        // Arrange
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> decision.present(null, result),
                "Should throw IllegalArgumentException for null context"
        );
        assertTrue(exception.getMessage().contains("Protection context"), "Error message should mention protection context");
    }

    @Test
    void testPresentWithNullSanitizationResult() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> decision.present(context, null),
                "Should throw IllegalArgumentException for null sanitization result"
        );
        assertTrue(exception.getMessage().contains("Sanitization result"), "Error message should mention sanitization result");
    }

    @Test
    void testPresentWithNoSensitiveInfo() {
        // Arrange
        String prompt = "This is a simple prompt without sensitive information.";
        ProtectionContext context = new ProtectionContext(prompt, SanitizationLevel.MEDIUM, false, false);
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), prompt, SanitizationLevel.MEDIUM);

        // Act
        PromptPresentationInfo presentationInfo = decision.present(context, result);

        // Assert
        assertNotNull(presentationInfo, "Presentation info should not be null");
        assertEquals(prompt, presentationInfo.getOriginalPrompt(), "Original prompt should match");
        assertEquals(prompt, presentationInfo.getSanitizedPromptPreview(), "Sanitized preview should match original");
        assertFalse(presentationInfo.hasSensitiveInfo(), "Should not have sensitive info");
        assertFalse(presentationInfo.isRequiresConfirmation(), "Should not require confirmation");
        assertEquals(0, presentationInfo.getSensitiveInfos().size(), "Should have 0 sensitive info items");
    }

    @Test
    void testPresentWithSensitiveInfo() {
        // Arrange
        String sanitizedPrompt = "My phone is 138****5678, please call me.";
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.PHONE_NUMBER, "13812345678", Severity.HIGH, 9, 21);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), sanitizedPrompt, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        PromptPresentationInfo presentationInfo = decision.present(context, result);

        // Assert
        assertNotNull(presentationInfo, "Presentation info should not be null");
        assertEquals(TEST_PROMPT, presentationInfo.getOriginalPrompt(), "Original prompt should match");
        assertEquals(sanitizedPrompt, presentationInfo.getSanitizedPromptPreview(), "Sanitized preview should match");
        assertTrue(presentationInfo.hasSensitiveInfo(), "Should have sensitive info");
        assertTrue(presentationInfo.isRequiresConfirmation(), "Should require confirmation");
        assertEquals(1, presentationInfo.getSensitiveInfos().size(), "Should have 1 sensitive info item");
    }

    @Test
    void testPresentWithConfirmationRequired() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, true);
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act
        PromptPresentationInfo presentationInfo = decision.present(context, result);

        // Assert
        assertTrue(presentationInfo.isRequiresConfirmation(), "Should require confirmation when context requires it");
    }

    @Test
    void testCollectDecisionWithNullPresentationInfo() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> decision.collectDecision(null),
                "Should throw IllegalArgumentException for null presentation info"
        );
        assertTrue(exception.getMessage().contains("Presentation info"), "Error message should mention presentation info");
    }

    @Test
    void testCollectDecisionReturnsRecommendedDecision() {
        // Arrange
        String sanitizedPrompt = "My phone is 138****5678, please call me.";
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.PHONE_NUMBER, "13812345678", Severity.HIGH, 9, 21);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), sanitizedPrompt, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        PromptPresentationInfo presentationInfo = decision.present(context, result);

        // Act
        UserDecisionResult userDecisionResult = decision.collectDecision(presentationInfo);

        // Assert
        assertNotNull(userDecisionResult, "User decision result should not be null");
        assertEquals(DecisionType.SEND_SANITIZED, userDecisionResult.getDecisionType(), "Should recommend SEND_SANITIZED for HIGH severity");
        assertEquals(sanitizedPrompt, userDecisionResult.getFinalPrompt(), "Final prompt should match sanitized prompt");
    }

    @Test
    void testProcessDecisionWithNullDecisionType() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> decision.processDecision(null, TEST_PROMPT),
                "Should throw IllegalArgumentException for null decision type"
        );
        assertTrue(exception.getMessage().contains("Decision type"), "Error message should mention decision type");
    }

    @Test
    void testProcessDecisionWithNullPrompt() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> decision.processDecision(DecisionType.SEND_ORIGINAL, null),
                "Should throw IllegalArgumentException for null prompt"
        );
        assertTrue(exception.getMessage().contains("Prompt"), "Error message should mention prompt");
    }

    @Test
    void testProcessDecisionWithEmptyPrompt() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> decision.processDecision(DecisionType.SEND_ORIGINAL, ""),
                "Should throw IllegalArgumentException for empty prompt"
        );
        assertTrue(exception.getMessage().contains("Prompt"), "Error message should mention prompt");
    }

    @Test
    void testProcessDecisionSendOriginal() {
        // Arrange
        String prompt = "This is my original prompt.";

        // Act
        UserDecisionResult result = decision.processDecision(DecisionType.SEND_ORIGINAL, prompt);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertEquals(DecisionType.SEND_ORIGINAL, result.getDecisionType(), "Decision type should be SEND_ORIGINAL");
        assertEquals(prompt, result.getFinalPrompt(), "Final prompt should match input");
        assertFalse(result.isCancellation(), "Should not be cancellation");
    }

    @Test
    void testProcessDecisionSendSanitized() {
        // Arrange
        String sanitizedPrompt = "My phone is 138****5678.";

        // Act
        UserDecisionResult result = decision.processDecision(DecisionType.SEND_SANITIZED, sanitizedPrompt);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertEquals(DecisionType.SEND_SANITIZED, result.getDecisionType(), "Decision type should be SEND_SANITIZED");
        assertEquals(sanitizedPrompt, result.getFinalPrompt(), "Final prompt should match input");
        assertFalse(result.isCancellation(), "Should not be cancellation");
    }

    @Test
    void testRequiresUserInteractionWithNullContext() {
        // Arrange
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(null, result);

        // Assert
        assertFalse(requiresInteraction, "Should not require interaction with null context");
    }

    @Test
    void testRequiresUserInteractionWithNullSanitizationResult() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(context, null);

        // Assert
        assertFalse(requiresInteraction, "Should not require interaction with null result");
    }

    @Test
    void testRequiresUserInteractionWithNoSensitiveInfo() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(context, result);

        // Assert
        assertFalse(requiresInteraction, "Should not require interaction without sensitive info");
    }

    @Test
    void testRequiresUserInteractionWithConfirmationRequired() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, true);
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(context, result);

        // Assert
        assertTrue(requiresInteraction, "Should require interaction when context requires confirmation");
    }

    @Test
    void testRequiresUserInteractionWithHighSeverity() {
        // Arrange
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.PHONE_NUMBER, "13812345678", Severity.HIGH, 9, 21);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), TEST_PROMPT, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(context, result);

        // Assert
        assertTrue(requiresInteraction, "Should require interaction with HIGH severity");
    }

    @Test
    void testRequiresUserInteractionWithMediumSeverity() {
        // Arrange
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.BUDGET, "budget 5000", Severity.MEDIUM, 0, 12);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), TEST_PROMPT, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(context, result);

        // Assert
        assertTrue(requiresInteraction, "Should require interaction with MEDIUM severity");
    }

    @Test
    void testRequiresUserInteractionWithLowSeverity() {
        // Arrange
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.NAME, "John", Severity.LOW, 0, 4);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), TEST_PROMPT, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        boolean requiresInteraction = decision.requiresUserInteraction(context, result);

        // Assert
        assertFalse(requiresInteraction, "Should not require interaction with LOW severity");
    }

    @Test
    void testGetRecommendedDecisionWithNullContext() {
        // Arrange
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(null, result);

        // Assert
        assertEquals(DecisionType.SEND_ORIGINAL, decisionType, "Should recommend SEND_ORIGINAL with null context");
    }

    @Test
    void testGetRecommendedDecisionWithNullResult() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(context, null);

        // Assert
        assertEquals(DecisionType.SEND_ORIGINAL, decisionType, "Should recommend SEND_ORIGINAL with null result");
    }

    @Test
    void testGetRecommendedDecisionWithNoSensitiveInfo() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        SanitizationResult result = new SanitizationResult(false, Collections.emptyList(), TEST_PROMPT, SanitizationLevel.MEDIUM);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(context, result);

        // Assert
        assertEquals(DecisionType.SEND_ORIGINAL, decisionType, "Should recommend SEND_ORIGINAL without sensitive info");
    }

    @Test
    void testGetRecommendedDecisionWithHighSeverity() {
        // Arrange
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.PHONE_NUMBER, "13812345678", Severity.HIGH, 9, 21);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), TEST_PROMPT, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(context, result);

        // Assert
        assertEquals(DecisionType.SEND_SANITIZED, decisionType, "Should recommend SEND_SANITIZED for HIGH severity");
    }

    @Test
    void testGetRecommendedDecisionWithMediumSeverity() {
        // Arrange
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.BUDGET, "budget 5000", Severity.MEDIUM, 0, 12);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), TEST_PROMPT, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(context, result);

        // Assert
        assertEquals(DecisionType.SEND_SANITIZED, decisionType, "Should recommend SEND_SANITIZED for MEDIUM severity");
    }

    @Test
    void testGetRecommendedDecisionWithLowSeverity() {
        // Arrange
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.NAME, "John", Severity.LOW, 0, 4);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), TEST_PROMPT, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(context, result);

        // Assert
        assertEquals(DecisionType.SEND_SANITIZED, decisionType, "Should recommend SEND_SANITIZED for LOW severity");
    }

    @Test
    void testGetRecommendedDecisionWithPresentationInfo() {
        // Arrange
        String sanitizedPrompt = "My phone is 138****5678.";
        SensitiveInfo info = new SensitiveInfo(SensitiveInfoType.PHONE_NUMBER, "13812345678", Severity.HIGH, 9, 21);
        SanitizationResult result = new SanitizationResult(true, Collections.singletonList(info), sanitizedPrompt, SanitizationLevel.MEDIUM);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        PromptPresentationInfo presentationInfo = decision.present(context, result);

        // Act
        DecisionType decisionType = decision.getRecommendedDecision(presentationInfo);

        // Assert
        assertNotNull(decisionType, "Decision type should not be null");
        assertEquals(DecisionType.SEND_SANITIZED, decisionType, "Should recommend SEND_SANITIZED for HIGH severity");
    }

    @Test
    void testGetRecommendedDecisionWithNullPresentationInfo() {
        // Act
        DecisionType decisionType = decision.getRecommendedDecision((PromptPresentationInfo) null);

        // Assert
        assertEquals(DecisionType.SEND_ORIGINAL, decisionType, "Should recommend SEND_ORIGINAL with null presentation info");
    }
}
