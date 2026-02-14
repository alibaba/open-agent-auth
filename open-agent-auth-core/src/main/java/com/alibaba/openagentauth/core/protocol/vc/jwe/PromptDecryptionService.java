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
package com.alibaba.openagentauth.core.protocol.vc.jwe;

import com.alibaba.openagentauth.core.crypto.jwe.JweDecoder;
import com.alibaba.openagentauth.core.exception.crypto.PromptDecryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Service for decrypting user prompts using JWE.
 * <p>
 * This service provides decryption for JWE-encrypted user prompts.
 * When encryption is disabled, it returns the input unchanged.
 * When encryption is enabled, it decrypts the JWE token.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This class is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see PromptEncryptionService
 * @since 1.0
 */
public class PromptDecryptionService {

    private static final Logger logger = LoggerFactory.getLogger(PromptDecryptionService.class);

    private final JweDecoder jweDecoder;
    private final boolean enabled;

    /**
     * Constructs a new PromptDecryptionService.
     *
     * @param jweDecoder the JWE decoder
     * @param enabled whether encryption is enabled
     * @throws NullPointerException if jweDecoder is null
     */
    public PromptDecryptionService(JweDecoder jweDecoder, boolean enabled) {
        this.jweDecoder = Objects.requireNonNull(jweDecoder, "jweDecoder must not be null");
        this.enabled = enabled;
        logger.info("PromptDecryptionService initialized, enabled: {}", enabled);
    }

    /**
     * Decrypts a prompt.
     * <p>
     * If encryption is disabled, returns the input unchanged.
     * If encryption is enabled, decrypts the JWE token.
     * If the input is not in JWE format, returns it unchanged.
     * </p>
     *
     * @param encryptedPrompt the encrypted JWE string or plaintext
     * @return the decrypted prompt or input if encryption is disabled or not in JWE format
     * @throws PromptDecryptionException if decryption fails
     * @throws IllegalArgumentException if encryptedPrompt is null
     */
    public String decryptPrompt(String encryptedPrompt) {
        Objects.requireNonNull(encryptedPrompt, "encryptedPrompt must not be null");

        if (!enabled) {
            logger.debug("Encryption is disabled, returning input as-is");
            return encryptedPrompt;
        }

        // Check if input is in JWE format (5 parts separated by dots)
        if (!isJweFormat(encryptedPrompt)) {
            logger.debug("Input is not in JWE format, returning as-is");
            return encryptedPrompt;
        }

        try {
            String decrypted = jweDecoder.decryptToString(encryptedPrompt);
            logger.debug("Prompt decrypted successfully");
            return decrypted;
        } catch (Exception e) {
            logger.error("Failed to decrypt prompt", e);
            throw new PromptDecryptionException("Failed to decrypt prompt", e);
        }
    }

    /**
     * Checks if the input string is in JWE format.
     * <p>
     * JWE compact serialization format consists of 5 parts separated by dots:
     * header.encryptedKey.iv.ciphertext.tag
     * </p>
     *
     * @param input the input string
     * @return true if the input is in JWE format, false otherwise
     */
    private boolean isJweFormat(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        // JWE has 5 parts separated by dots
        return input.chars().filter(ch -> ch == '.').count() == 4;
    }

    /**
     * Checks if encryption is enabled.
     *
     * @return true if encryption is enabled, false otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

}
