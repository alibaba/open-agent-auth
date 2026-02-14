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

import com.alibaba.openagentauth.core.crypto.jwe.JweEncoder;
import com.alibaba.openagentauth.core.protocol.vc.decision.DefaultUserPromptDecision;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DefaultPromptProtectionChain}.
 * <p>
 * These tests validate the three-layer prompt protection chain coordination:
 * </p>
 * <ul>
 *   <li>Orchestration of JWE encryption, sanitization, and user decision layers</li>
 *   <li>Dual detection mechanism for comprehensive protection</li>
 *   <li>User pre-approval support for faster processing</li>
 *   <li>Re-protection after user editing</li>
 *   <li>Proper error handling and validation</li>
 * </ul>
 *
 * @see DefaultPromptProtectionChain
 */
class DefaultPromptProtectionChainTest {

    private static final String TEST_PROMPT = "My phone is 13812345678, please call me.";
    private static final String SANITIZED_PROMPT = "My phone is 138****5678, please call me.";
    private static final String ENCRYPTED_PROMPT = "encrypted_jwe_token";

    private PromptEncryptionService encryptionService;
    private PromptSanitizer sanitizer;
    private UserPromptDecision userDecision;
    private DefaultPromptProtectionChain chain;

    @BeforeEach
    void setUp() {
        MockJweEncoder mockJweEncoder = new MockJweEncoder();
        encryptionService = new PromptEncryptionService(mockJweEncoder, true);
        sanitizer = new DefaultPromptSanitizer();
        userDecision = new DefaultUserPromptDecision();
        chain = new DefaultPromptProtectionChain(encryptionService, sanitizer, userDecision);
    }

    @Test
    void testConstructorWithAllNullParameters() {
        // Act
        DefaultPromptProtectionChain chainWithDefaults = new DefaultPromptProtectionChain(null, null, null);

        // Assert
        assertNotNull(chainWithDefaults, "Chain should be created with default implementations");
    }

    @Test
    void testProtectWithNullContext() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.protect(null),
                "Should throw IllegalArgumentException for null context"
        );
        assertTrue(exception.getMessage().contains("Protection context"), "Error message should mention protection context");
    }

    @Test
    void testProtectWithoutEncryption() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act
        ProtectionResult result = chain.protect(context);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertFalse(result.isEncrypted(), "Should not be encrypted");
        assertTrue(result.hasSensitiveInfo(), "Should have detected sensitive info");
        assertNotNull(result.getSanitizationResult(), "Sanitization result should not be null");
        assertNotNull(result.getUserDecision(), "User decision result should not be null");
    }

    @Test
    void testProtectWithEncryption() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, true, false);

        // Act
        ProtectionResult result = chain.protect(context);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertTrue(result.isEncrypted(), "Should be encrypted");
        assertEquals(ENCRYPTED_PROMPT, result.getProtectedPrompt(), "Protected prompt should be encrypted");
    }

    @Test
    void testProtectWithNoSensitiveInfo() {
        // Arrange
        String cleanPrompt = "This is a simple prompt without sensitive information.";
        ProtectionContext context = new ProtectionContext(cleanPrompt, SanitizationLevel.MEDIUM, false, false);

        // Act
        ProtectionResult result = chain.protect(context);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertFalse(result.hasSensitiveInfo(), "Should not have detected sensitive info");
    }

    @Test
    void testProtectWithDecisionWithNullContext() {
        // Arrange
        UserDecisionResult userDecisionResult = new UserDecisionResult(DecisionType.SEND_ORIGINAL, TEST_PROMPT);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.protectWithDecision(null, userDecisionResult),
                "Should throw IllegalArgumentException for null context"
        );
        assertTrue(exception.getMessage().contains("Protection context"), "Error message should mention protection context");
    }

    @Test
    void testProtectWithDecisionWithNullUserDecision() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.protectWithDecision(context, null),
                "Should throw IllegalArgumentException for null user decision"
        );
        assertTrue(exception.getMessage().contains("User decision"), "Error message should mention user decision");
    }

    @Test
    void testProtectWithDecisionSendOriginal() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        UserDecisionResult userDecisionResult = new UserDecisionResult(DecisionType.SEND_ORIGINAL, TEST_PROMPT);

        // Act
        ProtectionResult result = chain.protectWithDecision(context, userDecisionResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertEquals(TEST_PROMPT, result.getProtectedPrompt(), "Protected prompt should match original");
        assertEquals(DecisionType.SEND_ORIGINAL, result.getUserDecision().getDecisionType(), "Decision type should match");
    }

    @Test
    void testProtectWithDecisionSendSanitized() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        UserDecisionResult userDecisionResult = new UserDecisionResult(DecisionType.SEND_SANITIZED, SANITIZED_PROMPT);

        // Act
        ProtectionResult result = chain.protectWithDecision(context, userDecisionResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertEquals(DecisionType.SEND_SANITIZED, result.getUserDecision().getDecisionType(), "Decision type should match");
    }

    @Test
    void testProtectWithDecisionCancel() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        UserDecisionResult userDecisionResult = new UserDecisionResult(DecisionType.CANCEL);

        // Act
        ProtectionResult result = chain.protectWithDecision(context, userDecisionResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertFalse(result.isSuccess(), "Protection should fail due to cancellation");
        assertTrue(result.getErrorMessage().contains("User cancelled"), "Error message should mention cancellation");
    }

    @Test
    void testProtectWithDecisionWithEncryption() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, true, false);
        UserDecisionResult userDecisionResult = new UserDecisionResult(DecisionType.SEND_ORIGINAL, TEST_PROMPT);

        // Act
        ProtectionResult result = chain.protectWithDecision(context, userDecisionResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertTrue(result.isEncrypted(), "Should be encrypted");
        assertEquals(ENCRYPTED_PROMPT, result.getProtectedPrompt(), "Protected prompt should be encrypted");
    }

    @Test
    void testReProtectWithNullContext() {
        // Arrange
        ProtectionResult previousResult = createMockProtectionResult();

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.reProtect(null, "edited", previousResult),
                "Should throw IllegalArgumentException for null context"
        );
        assertTrue(exception.getMessage().contains("Protection context"), "Error message should mention protection context");
    }

    @Test
    void testReProtectWithNullEditedPrompt() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        ProtectionResult previousResult = createMockProtectionResult();

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.reProtect(context, null, previousResult),
                "Should throw IllegalArgumentException for null edited prompt"
        );
        assertTrue(exception.getMessage().contains("Edited prompt"), "Error message should mention edited prompt");
    }

    @Test
    void testReProtectWithEmptyEditedPrompt() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        ProtectionResult previousResult = createMockProtectionResult();

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.reProtect(context, "", previousResult),
                "Should throw IllegalArgumentException for empty edited prompt"
        );
        assertTrue(exception.getMessage().contains("Edited prompt"), "Error message should mention edited prompt");
    }

    @Test
    void testReProtectWithNullPreviousResult() {
        // Arrange
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chain.reProtect(context, "edited", null),
                "Should throw IllegalArgumentException for null previous result"
        );
        assertTrue(exception.getMessage().contains("Previous protection result"), "Error message should mention previous result");
    }

    @Test
    void testReProtectSuccessfully() {
        // Arrange
        String editedPrompt = "My phone is 13987654321, please call me.";
        ProtectionContext context = new ProtectionContext(editedPrompt, SanitizationLevel.MEDIUM, false, false);
        ProtectionResult previousResult = createMockProtectionResult();

        // Act
        ProtectionResult result = chain.reProtect(context, editedPrompt, previousResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Re-protection should succeed");
        assertTrue(result.hasSensitiveInfo(), "Should have detected sensitive info in edited prompt");
    }

    @Test
    void testReProtectWithEncryption() {
        // Arrange
        String editedPrompt = "My phone is 13987654321, please call me.";
        ProtectionContext context = new ProtectionContext(editedPrompt, SanitizationLevel.MEDIUM, true, false);
        ProtectionResult previousResult = createMockProtectionResult();

        // Act
        ProtectionResult result = chain.reProtect(context, editedPrompt, previousResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Re-protection should succeed");
        assertTrue(result.isEncrypted(), "Should be encrypted");
    }

    @Test
    void testReProtectWithNewSensitiveInfo() {
        // Arrange
        String originalPrompt = "Contact me for details.";
        String editedPrompt = "Contact me at 13812345678 for details.";
        ProtectionContext context = new ProtectionContext(editedPrompt, SanitizationLevel.MEDIUM, false, false);
        
        SanitizationResult previousSanitizationResult = new SanitizationResult(
            false, 
            Collections.emptyList(), 
            originalPrompt, 
            SanitizationLevel.MEDIUM
        );
        
        UserDecisionResult previousDecisionResult = new UserDecisionResult(DecisionType.SEND_ORIGINAL, originalPrompt);
        
        ProtectionResult previousResult = new ProtectionResult(
            originalPrompt,
            previousSanitizationResult,
            previousDecisionResult,
            false
        );

        // Act
        ProtectionResult result = chain.reProtect(context, editedPrompt, previousResult);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.hasSensitiveInfo(), "Should detect new sensitive info in edited prompt");
    }

    @Test
    void testProtectWithNullEncryptionServiceAndEncryptionEnabled() {
        // Arrange
        DefaultPromptProtectionChain chainWithoutEncryption = new DefaultPromptProtectionChain(null, sanitizer, userDecision);
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, true, false);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> chainWithoutEncryption.protect(context),
                "Should throw IllegalArgumentException when encryption is enabled but service is null"
        );
        assertTrue(exception.getMessage().contains("PromptEncryptionService"), "Error message should mention encryption service");
    }

    @Test
    void testProtectWithDifferentSanitizationLevels() {
        // Test with NONE level
        ProtectionContext noneContext = new ProtectionContext(TEST_PROMPT, SanitizationLevel.NONE, false, false);
        ProtectionResult noneResult = chain.protect(noneContext);
        assertTrue(noneResult.isSuccess(), "Should succeed with NONE level");
        
        // Test with LOW level
        ProtectionContext lowContext = new ProtectionContext(TEST_PROMPT, SanitizationLevel.LOW, false, false);
        ProtectionResult lowResult = chain.protect(lowContext);
        assertTrue(lowResult.isSuccess(), "Should succeed with LOW level");
        
        // Test with MEDIUM level
        ProtectionContext mediumContext = new ProtectionContext(TEST_PROMPT, SanitizationLevel.MEDIUM, false, false);
        ProtectionResult mediumResult = chain.protect(mediumContext);
        assertTrue(mediumResult.isSuccess(), "Should succeed with MEDIUM level");
        
        // Test with HIGH level
        ProtectionContext highContext = new ProtectionContext(TEST_PROMPT, SanitizationLevel.HIGH, false, false);
        ProtectionResult highResult = chain.protect(highContext);
        assertTrue(highResult.isSuccess(), "Should succeed with HIGH level");
    }

    @Test
    void testCompleteProtectionFlow() {
        // Arrange - A complete protection scenario with all layers
        ProtectionContext context = new ProtectionContext(TEST_PROMPT, SanitizationLevel.HIGH, true, true);

        // Act
        ProtectionResult result = chain.protect(context);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Protection should succeed");
        assertTrue(result.isEncrypted(), "Should be encrypted");
        assertTrue(result.hasSensitiveInfo(), "Should have detected sensitive info");
        
        SanitizationResult sanitizationResult = result.getSanitizationResult();
        assertNotNull(sanitizationResult, "Sanitization result should not be null");
        assertTrue(sanitizationResult.hasSensitiveInfo(), "Sanitization should have detected sensitive info");
        
        UserDecisionResult userDecisionResult = result.getUserDecision();
        assertNotNull(userDecisionResult, "User decision result should not be null");
        assertNotNull(userDecisionResult.getDecisionType(), "Decision type should not be null");
    }

    /**
     * Creates a mock protection result for testing.
     */
    private ProtectionResult createMockProtectionResult() {
        SanitizationResult sanitizationResult = new SanitizationResult(
            false,
            Collections.emptyList(),
            TEST_PROMPT,
            SanitizationLevel.MEDIUM
        );
        
        UserDecisionResult userDecisionResult = new UserDecisionResult(
            DecisionType.SEND_ORIGINAL,
            TEST_PROMPT
        );
        
        return new ProtectionResult(
            TEST_PROMPT,
            sanitizationResult,
            userDecisionResult,
            false
        );
    }

    /**
     * Mock implementation of JweEncoder for testing.
     */
    private static class MockJweEncoder implements JweEncoder {
        @Override
        public String encrypt(String plaintext) {
            return ENCRYPTED_PROMPT;
        }
        
        @Override
        public String encrypt(byte[] plaintext) {
            return ENCRYPTED_PROMPT;
        }
    }
}
