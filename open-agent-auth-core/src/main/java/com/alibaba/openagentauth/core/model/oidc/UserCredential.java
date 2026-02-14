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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import java.util.Objects;

/**
 * Represents user credentials stored in the user registry.
 * <p>
 * This class encapsulates user credentials and profile information
 * for authentication purposes within the user registry system.
 * It contains sensitive information such as hashed passwords and should
 * only be used internally by the authentication registry implementations.
 * </p>
 * <p>
 * <b>Security Note:</b> This class contains hashed password data.
 * It should never be serialized to external APIs or exposed in responses.
 * Use {@link UserInfo} for external
 * API responses.
 * </p>
 *
 * @since 1.0
 */
public class UserCredential {

    private final String subject;
    private final String hashedPassword;
    private final String email;
    private final String name;

    /**
     * Creates a new UserCredential instance.
     *
     * @param subject the subject identifier
     * @param hashedPassword the hashed password
     * @param email the email address
     * @param name the display name
     */
    public UserCredential(String subject, String hashedPassword, String email, String name) {
        this.subject = ValidationUtils.validateNotNull(subject, "Subject");
        this.hashedPassword = ValidationUtils.validateNotNull(hashedPassword, "Hashed password");
        this.email = email;
        this.name = name;
    }

    /**
     * Gets the subject identifier.
     *
     * @return the subject
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Gets the hashed password.
     *
     * @return the hashed password
     */
    public String getHashedPassword() {
        return hashedPassword;
    }

    /**
     * Gets the email address.
     *
     * @return the email, or null if not set
     */
    public String getEmail() {
        return email;
    }

    /**
     * Gets the display name.
     *
     * @return the name, or null if not set
     */
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserCredential that = (UserCredential) o;
        return Objects.equals(subject, that.subject);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject);
    }

    @Override
    public String toString() {
        return "UserCredential{" +
                "subject='" + subject + '\'' +
                ", email='" + email + '\'' +
                ", name='" + name + '\'' +
                '}';
    }
}