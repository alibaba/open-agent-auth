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
package com.alibaba.openagentauth.core.model.identity;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Represents the identity of a user in the Agent Operation Authorization framework.
 * <p>
 * This class encapsulates user identity information including unique identifier,
 * display name, email address, and other profile attributes. It is used throughout
 * the authentication and authorization process to identify users and their permissions.
 * </p>
 * <p>
 * <b>Identity Fields:</b></p>
 * <ul>
 *   <li><b>subject:</b> REQUIRED - Unique subject identifier</li>
 *   <li><b>name:</b> OPTIONAL - Display name</li>
 *   <li><b>email:</b> OPTIONAL - Email address</li>
 *   <li><b>emailVerified:</b> OPTIONAL - Email verification status</li>
 *   <li><b>attributes:</b> OPTIONAL - Additional custom attributes</li>
 * </ul>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserIdentity {

    /**
     * Subject identifier.
     * <p>
     * REQUIRED. The unique identifier for this user. This value is stable
     * and unique across all users in the system.
     * </p>
     */
    @JsonProperty("sub")
    private final String subject;

    /**
     * Display name.
     * <p>
     * OPTIONAL. The user's display name for presentation purposes.
     * </p>
     */
    @JsonProperty("name")
    private final String name;

    /**
     * Email address.
     * <p>
     * OPTIONAL. The user's email address.
     * </p>
     */
    @JsonProperty("email")
    private final String email;

    /**
     * Email verification status.
     * <p>
     * OPTIONAL. Indicates whether the email address has been verified.
     * </p>
     */
    @JsonProperty("email_verified")
    private final Boolean emailVerified;

    /**
     * Authentication time.
     * <p>
     * OPTIONAL. The time when the user was authenticated.
     * </p>
     */
    @JsonProperty("auth_time")
    private final Instant authTime;

    /**
     * Additional attributes.
     * <p>
     * OPTIONAL. Custom attributes specific to the application.
     * </p>
     */
    @JsonProperty("attributes")
    private final Map<String, Object> attributes;

    /**
     * Constructor for Jackson deserialization.
     */
    @JsonCreator
    public UserIdentity(
            @JsonProperty("sub") String subject,
            @JsonProperty("name") String name,
            @JsonProperty("email") String email,
            @JsonProperty("email_verified") Boolean emailVerified,
            @JsonProperty("auth_time") Instant authTime,
            @JsonProperty("attributes") Map<String, Object> attributes
    ) {
        this.subject = subject;
        this.name = name;
        this.email = email;
        this.emailVerified = emailVerified;
        this.authTime = authTime;
        this.attributes = attributes;
    }

    private UserIdentity(Builder builder) {
        this.subject = builder.subject;
        this.name = builder.name;
        this.email = builder.email;
        this.emailVerified = builder.emailVerified;
        this.authTime = builder.authTime;
        this.attributes = builder.attributes;
    }

    public String getSubject() {
        return subject;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public Instant getAuthTime() {
        return authTime;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserIdentity that = (UserIdentity) o;
        return Objects.equals(subject, that.subject) &&
               Objects.equals(name, that.name) &&
               Objects.equals(email, that.email) &&
               Objects.equals(emailVerified, that.emailVerified) &&
               Objects.equals(authTime, that.authTime) &&
               Objects.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, name, email, emailVerified, authTime, attributes);
    }

    @Override
    public String toString() {
        return "UserIdentity{" +
                "subject='" + subject + '\'' +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", emailVerified=" + emailVerified +
                ", authTime=" + authTime +
                ", attributes=" + attributes +
                '}';
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String subject;
        private String name;
        private String email;
        private Boolean emailVerified;
        private Instant authTime;
        private Map<String, Object> attributes;

        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder emailVerified(Boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }

        public Builder authTime(Instant authTime) {
            this.authTime = authTime;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = attributes;
            return this;
        }

        public UserIdentity build() {
            ValidationUtils.validateNotNull(subject, "Subject is required");
            return new UserIdentity(this);
        }
    }
}