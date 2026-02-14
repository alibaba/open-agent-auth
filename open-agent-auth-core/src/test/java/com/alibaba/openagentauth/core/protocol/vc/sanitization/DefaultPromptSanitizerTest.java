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
import com.alibaba.openagentauth.core.protocol.vc.model.SensitiveInfo;
import com.alibaba.openagentauth.core.protocol.vc.model.SensitiveInfoType;
import com.alibaba.openagentauth.core.protocol.vc.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DefaultPromptSanitizer}.
 * <p>
 * These tests validate the sensitive information detection and sanitization functionality:
 * </p>
 * <ul>
 *   <li>Detection of multiple sensitive information types (phone, email, ID card, bank card, budget, address, name)</li>
 *   <li>Configurable sanitization levels (NONE, LOW, MEDIUM, HIGH)</li>
 *   <li>Dual detection mechanism for comprehensive protection</li>
 *   <li>Proper masking patterns for different sensitivity levels</li>
 * </ul>
 *
 * @see DefaultPromptSanitizer
 */
class DefaultPromptSanitizerTest {

    private DefaultPromptSanitizer sanitizer;

    @BeforeEach
    void setUp() {
        sanitizer = new DefaultPromptSanitizer();
    }

    @Test
    void testSanitizeWithNullPrompt() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> sanitizer.sanitize(null, SanitizationLevel.MEDIUM),
                "Should throw IllegalArgumentException for null prompt"
        );
        assertTrue(exception.getMessage().contains("Prompt"), "Error message should mention prompt");
    }

    @Test
    void testSanitizeWithEmptyPrompt() {
        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> sanitizer.sanitize("", SanitizationLevel.MEDIUM),
                "Should throw IllegalArgumentException for empty prompt"
        );
        assertTrue(exception.getMessage().contains("Prompt"), "Error message should mention prompt");
    }

    @Test
    void testSanitizeWithNullLevel() {
        // Arrange
        String prompt = "Test prompt";

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> sanitizer.sanitize(prompt, null),
                "Should throw IllegalArgumentException for null level"
        );
        assertTrue(exception.getMessage().contains("Sanitization level"), "Error message should mention sanitization level");
    }

    @Test
    void testSanitizeWithNoSensitiveInfo() {
        // Arrange
        String prompt = "This is a simple test prompt without sensitive information.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertFalse(result.hasSensitiveInfo(), "Should not detect any sensitive info");
        assertEquals(prompt, result.getSanitizedPrompt(), "Sanitized prompt should match original");
        assertEquals(SanitizationLevel.MEDIUM, result.getAppliedLevel(), "Level should match");
        assertEquals(0, result.getSensitiveInfoCount(), "Should have 0 sensitive info items");
    }

    @Test
    void testDetectPhoneNumber() {
        // Arrange
        String prompt = "My phone number is 13812345678, please call me.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect phone number");
        assertEquals(1, result.getSensitiveInfoCount(), "Should detect 1 phone number");
        assertEquals(SensitiveInfoType.PHONE_NUMBER, result.getSensitiveInfos().get(0).getType(), "Type should be PHONE_NUMBER");
        assertTrue(result.getSanitizedPrompt().contains("****"), "Sanitized prompt should contain asterisks");
    }

    @Test
    void testDetectEmail() {
        // Arrange
        String prompt = "Contact me at test@example.com for more details.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect email");
        assertEquals(1, result.getSensitiveInfoCount(), "Should detect 1 email");
        assertEquals(SensitiveInfoType.EMAIL, result.getSensitiveInfos().get(0).getType(), "Type should be EMAIL");
        assertTrue(result.getSanitizedPrompt().contains("***"), "Sanitized prompt should contain asterisks");
    }

    @Test
    void testDetectIdCard() {
        // Arrange
        String prompt = "My ID card number is 110101199001011234";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect ID card");
    }

    @Test
    void testDetectBankCard() {
        // Arrange
        String prompt = "My bank card number is 6222021234567890 for payment.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect bank card");
        assertEquals(1, result.getSensitiveInfoCount(), "Should detect 1 bank card");
        assertEquals(SensitiveInfoType.BANK_CARD, result.getSensitiveInfos().get(0).getType(), "Type should be BANK_CARD");
        assertTrue(result.getSanitizedPrompt().contains("********"), "Sanitized prompt should contain asterisks");
    }

    @Test
    void testDetectBudget() {
        // Arrange
        String prompt = "My budget is 5000 for this project.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect budget");
        assertEquals(1, result.getSensitiveInfoCount(), "Should detect 1 budget");
        assertEquals(SensitiveInfoType.BUDGET, result.getSensitiveInfos().get(0).getType(), "Type should be BUDGET");
    }

    @Test
    void testDetectAddress() {
        // Arrange
        String prompt = "I live at st.123, New York.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect address");
        // Check if ADDRESS type is detected
        boolean hasAddress = result.getSensitiveInfos().stream()
                .anyMatch(info -> info.getType() == SensitiveInfoType.ADDRESS);
        assertTrue(hasAddress, "Should detect ADDRESS type");
    }

    @Test
    void testDetectChineseName() {
        // Arrange
        String prompt = "My name is Li Ming, nice to meet you.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect Chinese name");
        // Check if NAME type is detected (may detect multiple items including name)
        boolean hasName = result.getSensitiveInfos().stream()
                .anyMatch(info -> info.getType() == SensitiveInfoType.NAME);
        assertTrue(hasName, "Should detect NAME type");
    }

    @Test
    void testDetectEnglishName() {
        // Arrange
        String prompt = "My name is John Smith, nice to meet you.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect English name");
        // Check if NAME type is detected
        boolean hasName = result.getSensitiveInfos().stream()
                .anyMatch(info -> info.getType() == SensitiveInfoType.NAME);
        assertTrue(hasName, "Should detect NAME type");
    }

    @Test
    void testDetectMultipleSensitiveInfo() {
        // Arrange
        String prompt = "Contact ZhangSan at 13812345678 or test@example.com, ID: 110101199001011234.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect sensitive info");
        assertTrue(result.getSensitiveInfoCount() >= 2, "Should detect at least 2 items");
    }

    @Test
    void testSanitizeWithNoneLevel() {
        // Arrange
        String prompt = "My phone is 13812345678.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.NONE);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect sensitive info");
        assertEquals(prompt, result.getSanitizedPrompt(), "Sanitized prompt should match original with NONE level");
    }

    @Test
    void testSanitizeWithLowLevel() {
        // Arrange
        String prompt = "My phone is 13812345678.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.LOW);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect sensitive info");
        assertNotEquals(prompt, result.getSanitizedPrompt(), "Sanitized prompt should be different");
        assertTrue(result.getSanitizedPrompt().contains("***"), "Should contain asterisks");
    }

    @Test
    void testSanitizeWithMediumLevel() {
        // Arrange
        String prompt = "My phone is 13812345678.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect sensitive info");
        String sanitized = result.getSanitizedPrompt();
        assertTrue(sanitized.contains("138****"), "Should contain phone prefix");
        assertTrue(sanitized.contains("5678"), "Should contain phone suffix");
    }

    @Test
    void testSanitizeWithHighLevel() {
        // Arrange
        String prompt = "My phone is 13812345678.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.HIGH);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect sensitive info");
        assertTrue(result.getSanitizedPrompt().contains("[PHONE_NUMBER_REDACTED]"), "Should contain redacted placeholder");
        assertFalse(result.getSanitizedPrompt().contains("138"), "Should not contain original phone number");
    }

    @Test
    void testSanitizeEmailWithMediumLevel() {
        // Arrange
        String prompt = "Contact at test@example.com";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect email");
        String sanitized = result.getSanitizedPrompt();
        assertTrue(sanitized.contains("te***@"), "Should contain masked email prefix");
        assertTrue(sanitized.contains("@example.com"), "Should contain email domain");
    }

    @Test
    void testReDetectWithNullEditedPrompt() {
        // Arrange
        String prompt = "Test prompt";
        SanitizationResult previousResult = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> sanitizer.reDetect(null, previousResult, SanitizationLevel.MEDIUM),
                "Should throw IllegalArgumentException for null edited prompt"
        );
        assertTrue(exception.getMessage().contains("Edited prompt"), "Error message should mention edited prompt");
    }

    @Test
    void testReDetectWithEmptyEditedPrompt() {
        // Arrange
        String prompt = "Test prompt";
        SanitizationResult previousResult = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> sanitizer.reDetect("", previousResult, SanitizationLevel.MEDIUM),
                "Should throw IllegalArgumentException for empty edited prompt"
        );
        assertTrue(exception.getMessage().contains("Edited prompt"), "Error message should mention edited prompt");
    }

    @Test
    void testReDetectWithNullPreviousResult() {
        // Arrange
        String editedPrompt = "Test prompt";

        // Act
        SanitizationResult result = sanitizer.reDetect(editedPrompt, null, SanitizationLevel.MEDIUM);

        // Assert
        assertNotNull(result, "Result should not be null");
    }

    @Test
    void testReDetectWithNullLevel() {
        // Arrange
        String prompt = "Test prompt";
        SanitizationResult previousResult = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Act & Assert
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> sanitizer.reDetect("edited", previousResult, null),
                "Should throw IllegalArgumentException for null level"
        );
        assertTrue(exception.getMessage().contains("Sanitization level"), "Error message should mention sanitization level");
    }

    @Test
    void testReDetectDetectsNewSensitiveInfo() {
        // Arrange
        String originalPrompt = "Contact me for details.";
        SanitizationResult previousResult = sanitizer.sanitize(originalPrompt, SanitizationLevel.MEDIUM);
        String editedPrompt = "Contact me at 13812345678 for details.";

        // Act
        SanitizationResult result = sanitizer.reDetect(editedPrompt, previousResult, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(result.hasSensitiveInfo(), "Should detect new sensitive info");
        assertEquals(1, result.getSensitiveInfoCount(), "Should detect 1 new item");
    }

    @Test
    void testSensitiveInfoPosition() {
        // Arrange
        String prompt = "Call 13812345678 and 13987654321";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        List<SensitiveInfo> infos = result.getSensitiveInfos();
        assertEquals(2, infos.size(), "Should detect 2 phone numbers");
        
        SensitiveInfo first = infos.get(0);
        SensitiveInfo second = infos.get(1);
        
        assertEquals("13812345678", first.getValue(), "First phone should match");
        assertEquals("13987654321", second.getValue(), "Second phone should match");
        
        assertTrue(first.getStartIndex() < second.getStartIndex(), "First should start before second");
    }

    @Test
    void testSensitiveInfoSeverity() {
        // Arrange
        String prompt = "My phone is 13812345678.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.MEDIUM);

        // Assert
        SensitiveInfo info = result.getSensitiveInfos().get(0);
        assertEquals(Severity.HIGH, info.getSeverity(), "Phone number should have HIGH severity");
    }

    @Test
    void testPhoneNumberPatternValidation() {
        // Arrange
        String validPhone = "My phone is 13812345678.";
        String invalidPhone = "My phone is 12345678901."; // Invalid: starts with 1 but second digit is 2

        // Act
        SanitizationResult validResult = sanitizer.sanitize(validPhone, SanitizationLevel.MEDIUM);
        SanitizationResult invalidResult = sanitizer.sanitize(invalidPhone, SanitizationLevel.MEDIUM);

        // Assert
        assertTrue(validResult.hasSensitiveInfo(), "Should detect valid phone number");
        assertFalse(invalidResult.hasSensitiveInfo(), "Should not detect invalid phone number");
    }

    @Test
    void testCompleteSanitizationFlow() {
        // Arrange - A realistic prompt with multiple types of sensitive information
        String prompt = "Hello, my name is Li Ming. Please contact me at 13812345678 or liming@example.com. " +
                       "My ID card is 110101199001011234 and bank card is 6222021234567890. " +
                       "Budget is 10000 and I live at 100 Main Street.";

        // Act
        SanitizationResult result = sanitizer.sanitize(prompt, SanitizationLevel.HIGH);

        // Assert
        assertNotNull(result, "Result should not be null");
        assertTrue(result.hasSensitiveInfo(), "Should detect sensitive info");
        assertTrue(result.getSensitiveInfoCount() > 0, "Should detect at least one sensitive info");
        
        String sanitized = result.getSanitizedPrompt();
        
        // Verify no original sensitive data remains
        assertFalse(sanitized.contains("13812345678"), "Should not contain original phone");
        assertFalse(sanitized.contains("liming@example.com"), "Should not contain original email");
        assertFalse(sanitized.contains("110101199001011234"), "Should not contain original ID");
        assertFalse(sanitized.contains("6222021234567890"), "Should not contain original bank card");
        
        // Verify redaction markers
        assertTrue(sanitized.contains("[PHONE_NUMBER_REDACTED]") || sanitized.contains("[EMAIL_REDACTED]") || 
                   sanitized.contains("[ID_CARD_REDACTED]") || sanitized.contains("[BANK_CARD_REDACTED]"),
                   "Should contain at least one redaction marker");
    }
}
