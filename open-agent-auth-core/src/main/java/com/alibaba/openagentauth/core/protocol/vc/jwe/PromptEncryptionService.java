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

import com.alibaba.openagentauth.core.crypto.jwe.JweEncoder;
import com.alibaba.openagentauth.core.exception.crypto.PromptEncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Service for encrypting user prompts using JWE.
 * <p>
 * This service provides encryption protection for user original prompts.
 * When encryption is disabled, it returns the plaintext unchanged.
 * When encryption is enabled, it encrypts the prompt using JWE.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This class is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see PromptDecryptionService
 * @since 1.0
 */
public class PromptEncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(PromptEncryptionService.class);

    private final JweEncoder jweEncoder;
    private final boolean enabled;

    /**
     * Constructs a new PromptEncryptionService.
     *
     * @param jweEncoder the JWE encoder
     * @param enabled whether encryption is enabled
     * @throws NullPointerException if jweEncoder is null
     */
    public PromptEncryptionService(JweEncoder jweEncoder, boolean enabled) {
        this.jweEncoder = Objects.requireNonNull(jweEncoder, "jweEncoder must not be null");
        this.enabled = enabled;
        logger.info("PromptEncryptionService initialized, enabled: {}", enabled);
    }

    /**
     * Encrypts a prompt.
     * <p>
     * If encryption is disabled, returns the plaintext unchanged.
     * If encryption is enabled, encrypts the prompt using JWE.
     * </p>
     *
     * @param prompt the plaintext prompt
     * @return the encrypted JWE string or plaintext if encryption is disabled
     * @throws PromptEncryptionException if encryption fails
     * @throws IllegalArgumentException if prompt is null
     */
    public String encryptPrompt(String prompt) {
        Objects.requireNonNull(prompt, "prompt must not be null");

        if (!enabled) {
            logger.debug("Encryption is disabled, returning plaintext");
            return prompt;
        }

        try {
            String encrypted = jweEncoder.encrypt(prompt);
            logger.debug("Prompt encrypted successfully");
            return encrypted;
        } catch (Exception e) {
            logger.error("Failed to encrypt prompt", e);
            throw new PromptEncryptionException("Failed to encrypt prompt", e);
        }
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
