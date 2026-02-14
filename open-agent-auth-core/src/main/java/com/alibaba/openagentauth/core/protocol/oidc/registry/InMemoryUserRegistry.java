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
package com.alibaba.openagentauth.core.protocol.oidc.registry;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.exception.oidc.OidcRfcErrorCode;
import com.alibaba.openagentauth.core.model.oidc.UserCredential;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link UserRegistry}.
 * <p>
 * This implementation stores user credentials in memory and is suitable for
 * development and testing purposes. For production use, consider implementing
 * a custom {@link UserRegistry} with persistent storage.
 * </p>
 * <p>
 * <b>Security Note:</b></p>
 * This implementation uses SHA-256 for password hashing, which is suitable for
 * development and testing. For production, use stronger algorithms like Argon2,
 * BCrypt, or PBKDF2 with appropriate iterations and salt management.
 * </p>
 *
 * @since 1.0
 */
public class InMemoryUserRegistry implements UserRegistry {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryUserRegistry.class);

    /**
     * In-memory user storage.
     * <p>
     * Key: username
     * Value: UserCredential containing credentials and profile
     * </p>
     */
    private final Map<String, UserCredential> userStore;

    /**
     * Creates a new empty InMemoryUserRegistry.
     */
    public InMemoryUserRegistry() {
        this.userStore = new ConcurrentHashMap<>();
        logger.info("InMemoryUserRegistry initialized");
    }

    @Override
    public String authenticate(String username, String password) throws AuthenticationException {
        if (ValidationUtils.isNullOrEmpty(username)) {
            throw new AuthenticationException(OidcRfcErrorCode.INVALID_REQUEST, "Username cannot be empty");
        }
        if (ValidationUtils.isNullOrEmpty(password)) {
            throw new AuthenticationException(OidcRfcErrorCode.INVALID_REQUEST, "Password cannot be empty");
        }

        UserCredential credential = userStore.get(username);
        if (credential == null) {
            logger.warn("User not found: {}", username);
            throw new AuthenticationException(OidcRfcErrorCode.INVALID_GRANT, "Invalid username or password");
        }

        String hashedInputPassword = hashPassword(password);
        if (!hashedInputPassword.equals(credential.getHashedPassword())) {
            logger.warn("Invalid password for user: {}", username);
            throw new AuthenticationException(OidcRfcErrorCode.INVALID_GRANT, "Invalid username or password");
        }

        logger.debug("Authentication successful for user: {}", username);
        return credential.getSubject();
    }

    @Override
    public boolean userExists(String username) {
        return userStore.containsKey(username);
    }

    @Override
    public String getSubject(String username) {
        UserCredential credential = userStore.get(username);
        return credential != null ? credential.getSubject() : null;
    }

    @Override
    public String getEmail(String username) {
        UserCredential credential = userStore.get(username);
        return credential != null ? credential.getEmail() : null;
    }

    @Override
    public String getName(String username) {
        UserCredential credential = userStore.get(username);
        return credential != null ? credential.getName() : null;
    }

    /**
     * Adds a user to the registry.
     *
     * @param username the username
     * @param password the plain text password (will be hashed)
     * @param subject the subject identifier
     * @param email the email address
     * @param name the display name
     */
    public void addUser(String username, String password, String subject, String email, String name) {
        String hashedPassword = hashPassword(password);
        UserCredential credential = new UserCredential(subject, hashedPassword, email, name);
        userStore.put(username, credential);
        logger.debug("Added user: {} with subject: {}", username, subject);
    }

    /**
     * Removes a user from the registry.
     *
     * @param username the username to remove
     */
    public void removeUser(String username) {
        userStore.remove(username);
        logger.debug("Removed user: {}", username);
    }

    /**
     * Gets the number of users in the registry.
     *
     * @return the user count
     */
    public int getUserCount() {
        return userStore.size();
    }

    /**
     * Gets all usernames in the registry.
     *
     * @return a set of usernames
     */
    public java.util.Set<String> getUsernames() {
        return new java.util.HashSet<>(userStore.keySet());
    }

    /**
     * Hashes a password using SHA-256.
     * <p>
     * <b>Security Note:</b> This is a simple hash for development/testing.
     * For production, use Argon2, BCrypt, or PBKDF2 with proper salt.
     * </p>
     *
     * @param password the plain text password
     * @return the hashed password (Base64 encoded)
     */
    private String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to hash password", e);
            throw new RuntimeException("Password hashing algorithm not available", e);
        }
    }
}