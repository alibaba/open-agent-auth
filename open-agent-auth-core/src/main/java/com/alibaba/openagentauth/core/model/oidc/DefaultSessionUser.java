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
package com.alibaba.openagentauth.core.model.oidc;

/**
 * Simple session-based user model for IDP login scenarios.
 * <p>
 * This class represents a user in the Identity Provider system with session-based authentication.
 * It encapsulates user information including authentication credentials and profile data.
 * This implementation is designed for simple session management scenarios where user
 * information needs to be stored and retrieved from HTTP sessions.
 * </p>
 * <p>
 * <b>Key Characteristics:</b>
 * </p>
 * <ul>
 *   <li><b>Session-Oriented:</b> Designed for HTTP session-based authentication flows</li>
 *   <li><b>Lightweight:</b> Minimal overhead for storing user session data</li>
 *   <li><b>Immutable:</b> All fields are final, ensuring thread safety</li>
 *   <li><b>Builder Pattern:</b> Provides fluent API for constructing user instances</li>
 * </ul>
 * <p>
 * <b>Note:</b> This is a simple session-based user model. For production systems
 * with more complex requirements (e.g., distributed sessions, JWT tokens, etc.),
 * consider implementing custom user models by extending {@link SessionUser}.
 * </p>
 *
 * @since 1.0
 */
public class DefaultSessionUser implements SessionUser {
    
    /**
     * The unique subject identifier for this user.
     * <p>
     * This is a stable, unique identifier that represents the user across all systems.
     * In OpenID Connect, this corresponds to the {@code sub} claim in the ID Token.
     * Unlike {@link #username}, the subject should never change and should not contain
     * personally identifiable information (PII).
     * </p>
     */
    private final String subject;
    
    /**
     * The username used for authentication.
     * <p>
     * This is the credential identifier used by the user to log into the system.
     * It may be changed by the user or administrator, unlike the {@link #subject}.
     * </p>
     */
    private final String username;
    
    /**
     * The password credential for authentication.
     * <p>
     * <b>Security Warning:</b> In production systems, passwords should be securely hashed
     * using strong algorithms (e.g., BCrypt, Argon2, PBKDF2) with appropriate salt.
     * Storing plain-text passwords is a security vulnerability and should never be done
     * in production environments.
     * </p>
     */
    private final String password;
    
    /**
     * The full display name of the user.
     * <p>
     * This is the human-readable name of the user, typically their first and last name combined.
     * In OpenID Connect, this corresponds to the {@code name} claim.
     * </p>
     */
    private final String name;
    
    /**
     * The email address of the user.
     * <p>
     * This is the primary email address associated with the user account.
     * In OpenID Connect, this corresponds to the {@code email} claim.
     * The email should be validated and unique within the system.
     * </p>
     */
    private final String email;
    
    /**
     * The preferred username for display purposes.
     * <p>
     * This is the username that the user prefers to be addressed by in the application.
     * It may differ from the {@link #username} used for authentication.
     * In OpenID Connect, this corresponds to the {@code preferred_username} claim.
     * </p>
     */
    private final String preferredUsername;

    /**
     * Private constructor to enforce use of the {@link Builder} pattern.
     * 
     * @param builder the builder instance containing all user properties
     */
    private DefaultSessionUser(Builder builder) {
        this.subject = builder.subject;
        this.username = builder.username;
        this.password = builder.password;
        this.name = builder.name;
        this.email = builder.email;
        this.preferredUsername = builder.preferredUsername;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public String getPreferredUsername() {
        return preferredUsername;
    }

    /**
     * Creates a new {@link Builder} instance for constructing {@link DefaultSessionUser} objects.
     * <p>
     * This method provides a fluent API for building user instances with optional properties.
     * Example usage:
     * <pre>{@code
     * SimpleSessionUser user = SimpleSessionUser.builder()
     *     .subject("user_123")
     *     .username("alice")
     *     .password("password123")
     *     .name("Alice Smith")
     *     .email("alice@example.com")
     *     .preferredUsername("alice")
     *     .build();
     * }</pre>
     * </p>
     * 
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for constructing {@link DefaultSessionUser} instances.
     * <p>
     * This class implements the Builder pattern to provide a fluent API for creating
     * user objects. All setter methods return {@code this} to allow method chaining.
     * The {@link #build()} method validates and constructs the immutable {@link DefaultSessionUser} instance.
     * </p>
     * <p>
     * <b>Usage Example:</b>
     * <pre>{@code
     * SimpleSessionUser user = SimpleSessionUser.builder()
     *     .subject("user_123")
     *     .username("alice")
     *     .password("password123")
     *     .name("Alice Smith")
     *     .email("alice@example.com")
     *     .preferredUsername("alice")
     *     .build();
     * }</pre>
     * </p>
     */
    public static class Builder {
        private String subject;
        private String username;
        private String password;
        private String name;
        private String email;
        private String preferredUsername;

        /**
         * Sets the subject identifier for the user.
         * <p>
         * This should be a stable, unique identifier that never changes.
         * </p>
         * 
         * @param subject the unique subject identifier
         * @return this builder instance for method chaining
         */
        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        /**
         * Sets the username for authentication.
         * <p>
         * This is the credential identifier used for login.
         * </p>
         * 
         * @param username the username
         * @return this builder instance for method chaining
         */
        public Builder username(String username) {
            this.username = username;
            return this;
        }

        /**
         * Sets the password for authentication.
         * <p>
         * <b>Security Warning:</b> In production, passwords should be securely hashed
         * before being passed to this method.
         * </p>
         * 
         * @param password the password credential
         * @return this builder instance for method chaining
         */
        public Builder password(String password) {
            this.password = password;
            return this;
        }

        /**
         * Sets the full display name of the user.
         * <p>
         * This is typically the user's first and last name combined.
         * </p>
         * 
         * @param name the display name
         * @return this builder instance for method chaining
         */
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        /**
         * Sets the email address of the user.
         * <p>
         * This should be a validated, unique email address.
         * </p>
         * 
         * @param email the email address
         * @return this builder instance for method chaining
         */
        public Builder email(String email) {
            this.email = email;
            return this;
        }

        /**
         * Sets the preferred username for display purposes.
         * <p>
         * This may differ from the authentication username.
         * </p>
         * 
         * @param preferredUsername the preferred username
         * @return this builder instance for method chaining
         */
        public Builder preferredUsername(String preferredUsername) {
            this.preferredUsername = preferredUsername;
            return this;
        }

        /**
         * Builds and returns a new {@link DefaultSessionUser} instance with the configured properties.
         * <p>
         * The returned instance is immutable and thread-safe.
         * </p>
         * 
         * @return a new SimpleSessionUser instance
         */
        public DefaultSessionUser build() {
            return new DefaultSessionUser(this);
        }
    }
}
