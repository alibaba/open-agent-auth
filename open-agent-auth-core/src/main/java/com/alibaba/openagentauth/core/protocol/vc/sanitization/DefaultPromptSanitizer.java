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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Default implementation of prompt sanitization with dual detection mechanism.
 * <p>
 * This implementation provides comprehensive sensitive information detection and
 * sanitization capabilities. It implements the dual detection mechanism:
 * <ol>
 *   <li>Initial pre-sanitization detection when the prompt is first submitted</li>
 *   <li>Real-time re-detection after user editing to catch newly introduced sensitive information</li>
 * </ol>
 * </p>
 * <p>
 * Key features:
 * <ul>
 *   <li>Support for multiple sensitive information types (phone, email, ID card, bank card, budget, address, name)</li>
 *   <li>Configurable sanitization levels (NONE, LOW, MEDIUM, HIGH)</li>
 *   <li>Dual detection mechanism for comprehensive protection</li>
 *   <li>Pattern-based detection using regular expressions</li>
 *   <li>Severity-based default handling</li>
 *   <li>Thread-safe implementation following Effective Java Item 70</li>
 * </ul>
 * </p>
 * <p>
 * This class is designed to be thread-safe and can be safely shared across
 * multiple threads.
 * </p>
 *
 * @since 1.0
 * @see PromptSanitizer
 */
public class DefaultPromptSanitizer implements PromptSanitizer {
    
    private static final Logger logger = LoggerFactory.getLogger(DefaultPromptSanitizer.class);
    
    /**
     * Pattern for detecting Chinese mobile phone numbers (11 digits starting with 1).
     */
    private static final Pattern PHONE_PATTERN = Pattern.compile("1[3-9]\\d{9}");
    
    /**
     * Pattern for detecting email addresses.
     */
    private static final Pattern EMAIL_PATTERN = 
        Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    
    /**
     * Pattern for detecting Chinese ID card numbers (18 digits).
     */
    private static final Pattern ID_CARD_PATTERN = Pattern.compile("\\d{17}[\\dXx]");
    
    /**
     * Pattern for detecting bank card numbers (16-19 digits).
     */
    private static final Pattern BANK_CARD_PATTERN = Pattern.compile("\\d{13,19}");
    
    /**
     * Pattern for detecting budget information.
     */
    private static final Pattern BUDGET_PATTERN = Pattern.compile("budget.*\\d+.*", Pattern.CASE_INSENSITIVE);
    
    /**
     * Pattern for detecting physical addresses.
     */
    private static final Pattern ADDRESS_PATTERN = Pattern.compile(
        "\\b(street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|place|pl|square|sq)[\\s.]*\\d+", Pattern.CASE_INSENSITIVE);
    
    /**
     * Pattern for detecting Chinese names (2-4 Chinese characters).
     */
    private static final Pattern CHINESE_NAME_PATTERN = Pattern.compile("[\\u4e00-\\u9fa5]{2,4}");
    
    /**
     * Pattern for detecting English names (First Last format).
     */
    private static final Pattern ENGLISH_NAME_PATTERN = Pattern.compile("[A-Z][a-z]+\\s+[A-Z][a-z]+");
    
    /**
     * Constructs a new DefaultPromptSanitizer instance.
     * <p>
     * This constructor performs necessary initialization. The implementation
     * is stateless and thread-safe, following Effective Java Item 70.
     * </p>
     */
    public DefaultPromptSanitizer() {
        logger.debug("DefaultPromptSanitizer initialized");
    }
    
    /**
     * Detects sensitive information in the prompt and applies sanitization.
     *
     * @param prompt the prompt text to sanitize
     * @param level the sanitization level to apply
     * @return the sanitization result containing detected information and sanitized text
     */
    @Override
    public SanitizationResult sanitize(String prompt, SanitizationLevel level) {
        if (prompt == null || prompt.isEmpty()) {
            throw new IllegalArgumentException("Prompt cannot be null or empty");
        }
        if (level == null) {
            throw new IllegalArgumentException("Sanitization level cannot be null");
        }
        
        logger.debug("Sanitizing prompt (length: {}, level: {})", prompt.length(), level);
        
        List<SensitiveInfo> sensitiveInfos = detectSensitiveInfo(prompt);
        String sanitizedPrompt = applySanitization(prompt, sensitiveInfos, level);
        
        SanitizationResult result = new SanitizationResult(
            !sensitiveInfos.isEmpty(),
            sensitiveInfos,
            sanitizedPrompt,
            level
        );
        
        logger.debug("Sanitization complete: {} items detected", sensitiveInfos.size());
        return result;
    }
    
    /**
     * Re-detects sensitive information after user editing.
     * <p>
     * This method implements the second part of the dual detection mechanism.
     * It compares the edited prompt with the previous detection to identify
     * newly introduced sensitive information.
     * </p>
     *
     * @param editedPrompt the edited prompt text
     * @param previousResult the previous sanitization result for comparison
     * @param level the sanitization level to apply
     * @return the sanitization result with newly detected information
     */
    @Override
    public SanitizationResult reDetect(String editedPrompt, SanitizationResult previousResult, SanitizationLevel level) {
        if (editedPrompt == null || editedPrompt.isEmpty()) {
            throw new IllegalArgumentException("Edited prompt cannot be null or empty");
        }
        if (level == null) {
            throw new IllegalArgumentException("Sanitization level cannot be null");
        }
        
        logger.debug("Re-detecting sensitive information after editing (length: {})", editedPrompt.length());
        
        // Perform full detection on edited prompt
        List<SensitiveInfo> currentInfos = detectSensitiveInfo(editedPrompt);
        
        // Compare with previous results to identify new items
        List<SensitiveInfo> newInfos = identifyNewSensitiveInfo(currentInfos, previousResult);
        
        if (!newInfos.isEmpty()) {
            logger.warn("New sensitive information detected after editing: {} items", newInfos.size());
        }
        
        String sanitizedPrompt = applySanitization(editedPrompt, currentInfos, level);
        
        return new SanitizationResult(
            !currentInfos.isEmpty(),
            currentInfos,
            sanitizedPrompt,
            level
        );
    }
    
    /**
     * Detects all sensitive information in the prompt.
     * <p>
     * This method scans the prompt using all configured patterns and returns
     * a list of detected sensitive information items, sorted by severity and position.
     * </p>
     *
     * @param prompt the prompt text to scan
     * @return list of detected sensitive information items
     */
    private List<SensitiveInfo> detectSensitiveInfo(String prompt) {
        List<SensitiveInfo> infos = new ArrayList<>();
        
        // Detect phone numbers
        detectWithPattern(prompt, PHONE_PATTERN, SensitiveInfoType.PHONE_NUMBER, infos);
        
        // Detect email addresses
        detectWithPattern(prompt, EMAIL_PATTERN, SensitiveInfoType.EMAIL, infos);
        
        // Detect ID card numbers
        detectWithPattern(prompt, ID_CARD_PATTERN, SensitiveInfoType.ID_CARD, infos);
        
        // Detect bank card numbers
        detectWithPattern(prompt, BANK_CARD_PATTERN, SensitiveInfoType.BANK_CARD, infos);
        
        // Detect budget information
        detectWithPattern(prompt, BUDGET_PATTERN, SensitiveInfoType.BUDGET, infos);
        
        // Detect physical addresses
        detectWithPattern(prompt, ADDRESS_PATTERN, SensitiveInfoType.ADDRESS, infos);
        
        // Detect names (Chinese)
        detectWithPattern(prompt, CHINESE_NAME_PATTERN, SensitiveInfoType.NAME, infos);
        
        // Detect names (English)
        detectWithPattern(prompt, ENGLISH_NAME_PATTERN, SensitiveInfoType.NAME, infos);
        
        // Sort by severity (HIGH first) and then by start index
        infos.sort(Comparator
            .comparing(SensitiveInfo::getSeverity)
            .reversed()
            .thenComparingInt(SensitiveInfo::getStartIndex));
        
        return infos;
    }
    
    /**
     * Detects sensitive information using a specific pattern.
     *
     * @param prompt the prompt text to scan
     * @param pattern the pattern to use for detection
     * @param type the sensitive information type
     * @param infos the list to which detected items will be added
     */
    private void detectWithPattern(String prompt, Pattern pattern, SensitiveInfoType type, 
                                   List<SensitiveInfo> infos) {
        Matcher matcher = pattern.matcher(prompt);
        while (matcher.find()) {
            String value = matcher.group();
            int start = matcher.start();
            int end = matcher.end();
            
            SensitiveInfo info = new SensitiveInfo(type, value, type.getSeverity(), start, end);
            infos.add(info);
            
            logger.trace("Detected {}: '{}' at position {}-{}", type, value, start, end);
        }
    }
    
    /**
     * Applies sanitization to the prompt based on detected sensitive information.
     *
     * @param prompt the original prompt text
     * @param sensitiveInfos list of detected sensitive information items
     * @param level the sanitization level to apply
     * @return the sanitized prompt text
     */
    private String applySanitization(String prompt, List<SensitiveInfo> sensitiveInfos, SanitizationLevel level) {
        if (level == SanitizationLevel.NONE || sensitiveInfos.isEmpty()) {
            return prompt;
        }
        
        // Build a map of replacements (end index -> replacement text)
        // Use TreeMap for sorted iteration from end to start
        Map<Integer, String> replacements = new TreeMap<>();
        
        for (SensitiveInfo info : sensitiveInfos) {
            String replacement = generateReplacement(info, level);
            replacements.put(info.getEndIndex(), replacement);
        }
        
        // Apply replacements from end to start to preserve indices
        StringBuilder result = new StringBuilder(prompt);
        int offset = 0;
        
        for (Map.Entry<Integer, String> entry : replacements.entrySet()) {
            int end = entry.getKey();
            String replacement = entry.getValue();
            
            // Find the corresponding SensitiveInfo
            SensitiveInfo info = findInfoByEndIndex(sensitiveInfos, end);
            if (info != null) {
                result.replace(info.getStartIndex() + offset, end + offset, replacement);
                offset += replacement.length() - (end - info.getStartIndex());
            }
        }
        
        return result.toString();
    }
    
    /**
     * Generates a replacement string based on the sanitization level.
     *
     * @param info the sensitive information to replace
     * @param level the sanitization level
     * @return the replacement string
     */
    private String generateReplacement(SensitiveInfo info, SanitizationLevel level) {
        String value = info.getValue();
        SensitiveInfoType type = info.getType();

        return switch (level) {
            case LOW -> applyLowLevelMasking(value, type);
            case MEDIUM -> applyMediumLevelMasking(value, type);
            case HIGH -> applyHighLevelMasking(type);
            default -> value;
        };
    }
    
    /**
     * Applies low-level masking (preserves some information).
     */
    private String applyLowLevelMasking(String value, SensitiveInfoType type) {
        if (value.length() <= 2) {
            return "**";
        }
        
        // Keep first and last characters, mask middle
        return value.charAt(0) + "***" + value.charAt(value.length() - 1);
    }
    
    /**
     * Applies medium-level masking (standard patterns).
     */
    private String applyMediumLevelMasking(String value, SensitiveInfoType type) {
        switch (type) {
            case PHONE_NUMBER:
                // 138****8000
                if (value.length() >= 7) {
                    return value.substring(0, 3) + "****" + value.substring(7);
                }
                break;
                
            case EMAIL:
                // u***@example.com
                int atIndex = value.indexOf('@');
                if (atIndex > 1) {
                    return value.substring(0, 2) + "***" + value.substring(atIndex);
                }
                break;
                
            case ID_CARD:
                // 110***********1234
                if (value.length() >= 10) {
                    return value.substring(0, 3) + "***********" + value.substring(value.length() - 4);
                }
                break;
                
            case BANK_CARD:
                // 6222********1234
                if (value.length() >= 12) {
                    return value.substring(0, 4) + "********" + value.substring(value.length() - 4);
                }
                break;
                
            default:
                // Default medium masking
                return applyLowLevelMasking(value, type);
        }
        
        return applyLowLevelMasking(value, type);
    }
    
    /**
     * Applies high-level masking (complete replacement).
     */
    private String applyHighLevelMasking(SensitiveInfoType type) {
        return "[" + type.name() + "_REDACTED]";
    }
    
    /**
     * Finds a SensitiveInfo by its end index.
     */
    private SensitiveInfo findInfoByEndIndex(List<SensitiveInfo> infos, int endIndex) {
        for (SensitiveInfo info : infos) {
            if (info.getEndIndex() == endIndex) {
                return info;
            }
        }
        return null;
    }
    
    /**
     * Identifies newly introduced sensitive information compared to previous detection.
     *
     * @param currentInfos current detection results
     * @param previousResult previous sanitization result
     * @return list of newly detected sensitive information items
     */
    private List<SensitiveInfo> identifyNewSensitiveInfo(List<SensitiveInfo> currentInfos, 
                                                          SanitizationResult previousResult) {
        List<SensitiveInfo> newInfos = new ArrayList<>();
        
        if (previousResult == null || previousResult.getSensitiveInfos() == null) {
            // No previous result, consider all current items as new
            return newInfos;
        }
        
        List<SensitiveInfo> previousInfos = previousResult.getSensitiveInfos();
        
        // Compare current and previous detections
        for (SensitiveInfo currentInfo : currentInfos) {
            boolean isNew = true;
            
            // Check if this sensitive info existed in previous detection
            for (SensitiveInfo previousInfo : previousInfos) {
                if (isSameSensitiveInfo(currentInfo, previousInfo)) {
                    isNew = false;
                    break;
                }
            }
            
            if (isNew) {
                newInfos.add(currentInfo);
            }
        }
        
        return newInfos;
    }
    
    /**
     * Checks if two sensitive info items represent the same information.
     * <p>
     * Two items are considered the same if they have:
     * <ul>
     *   <li>The same type</li>
     *   <li>The same value</li>
     *   <li>The same or overlapping position in the text</li>
     * </ul>
     * </p>
     *
     * @param info1 the first sensitive info item
     * @param info2 the second sensitive info item
     * @return true if the items represent the same information, false otherwise
     */
    private boolean isSameSensitiveInfo(SensitiveInfo info1, SensitiveInfo info2) {
        // Check type
        if (info1.getType() != info2.getType()) {
            return false;
        }
        
        // Check value
        if (!info1.getValue().equals(info2.getValue())) {
            return false;
        }
        
        // Check if positions overlap or are the same
        // Allow for some flexibility in position due to text edits
        int positionDelta = Math.abs(info1.getStartIndex() - info2.getStartIndex());
        return positionDelta <= 10; // Allow up to 10 characters difference
    }
}