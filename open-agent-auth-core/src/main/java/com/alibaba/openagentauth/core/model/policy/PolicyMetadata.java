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
package com.alibaba.openagentauth.core.model.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Represents metadata associated with a registered policy.
 * <p>
 * Policy metadata contains lifecycle information, versioning, and custom attributes
 * that help manage policies throughout their lifetime. This information is essential
 * for policy auditing, governance, and lifecycle management.
 * </p>
 * <p>
 * <b>Metadata Fields:</b></p>
 * <table border="1">
 *   <tr><th>Field</th><th>Description</th><th>Status</th></tr>
 *   <tr><td>version</td><td>Policy version for tracking changes</td><td>REQUIRED</td></tr>
 *   <tr><td>created_at</td><td>Timestamp when the policy was created</td><td>REQUIRED</td></tr>
 *   <tr><td>created_by</td><td>Entity that created the policy (agent ID or user ID)</td><td>REQUIRED</td></tr>
 *   <tr><td>expiration_time</td><td>Timestamp when the policy expires</td><td>OPTIONAL</td></tr>
 *   <tr><td>tags</td><td>Key-value pairs for policy categorization</td><td>OPTIONAL</td></tr>
 * </table>
 *
 * @see Policy
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyMetadata {

    /**
     * Policy version.
     * <p>
     * Version number for tracking policy changes and updates.
     * Format: Semantic Versioning (e.g., "1.0.0", "1.1.0").
     * This field is REQUIRED.
     * </p>
     */
    @JsonProperty("version")
    private final String version;

    /**
     * Creation timestamp.
     * <p>
     * The time when the policy was registered with the Authorization Server.
     * This field is REQUIRED and MUST conform to ISO 8601 UTC format.
     * </p>
     */
    @JsonProperty("created_at")
    private final Instant createdAt;

    /**
     * Creator identifier.
     * <p>
     * The entity that created the policy. This could be:
     * <ul>
     *   <li>An agent ID (if the policy was proposed by an agent)</li>
     *   <li>A user ID (if the policy was created by an administrator)</li>
     *   <li>A system identifier (if the policy is a system default)</li>
     * </ul>
     * This field is REQUIRED.
     * </p>
     */
    @JsonProperty("created_by")
    private final String createdBy;

    /**
     * Expiration timestamp.
     * <p>
     * The time when the policy expires and should no longer be used.
     * This field is OPTIONAL. If not set, the policy does not expire.
     * When set, it MUST conform to ISO 8601 UTC format.
     * </p>
     */
    @JsonProperty("expiration_time")
    private final Instant expirationTime;

    /**
     * Custom tags or attributes.
     * <p>
     * Key-value pairs for policy categorization, indexing, and filtering.
     * Common uses include:
     * <ul>
     *   <li>"environment": "production", "staging", "development"</li>
     *   <li>"category": "finance", "healthcare", "ecommerce"</li>
     *   <li>"sensitivity": "high", "medium", "low"</li>
     * </ul>
     * This field is OPTIONAL.
     * </p>
     */
    @JsonProperty("tags")
    private final Map<String, String> tags;

    /**
     * Creates a new PolicyMetadata instance.
     *
     * @param version         the policy version
     * @param createdAt       the creation timestamp
     * @param createdBy       the creator identifier
     * @param expirationTime  the expiration timestamp
     * @param tags            the custom tags
     */
    @JsonCreator
    private PolicyMetadata(
            @JsonProperty("version") String version,
            @JsonProperty("created_at") Instant createdAt,
            @JsonProperty("created_by") String createdBy,
            @JsonProperty("expiration_time") Instant expirationTime,
            @JsonProperty("tags") Map<String, String> tags) {
        this.version = version;
        this.createdAt = createdAt;
        this.createdBy = createdBy;
        this.expirationTime = expirationTime;
        this.tags = tags;
    }

    /**
     * Gets the policy version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Gets the creation timestamp.
     *
     * @return the creation time
     */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Gets the creator identifier.
     *
     * @return the creator ID
     */
    public String getCreatedBy() {
        return createdBy;
    }

    /**
     * Gets the expiration timestamp.
     *
     * @return the expiration time, or null if not set
     */
    public Instant getExpirationTime() {
        return expirationTime;
    }

    /**
     * Gets the custom tags.
     *
     * @return the tags map, or null if not set
     */
    public Map<String, String> getTags() {
        return tags;
    }

    /**
     * Gets a tag value by key.
     *
     * @param key the tag key
     * @return the tag value, or null if not found
     */
    public String getTag(String key) {
        return tags != null ? tags.get(key) : null;
    }

    /**
     * Checks if the policy has expired.
     *
     * @return true if the policy is expired, false otherwise
     */
    public boolean isExpired() {
        return expirationTime != null && Instant.now().isAfter(expirationTime);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyMetadata that = (PolicyMetadata) o;
        return Objects.equals(version, that.version) &&
                Objects.equals(createdAt, that.createdAt) &&
                Objects.equals(createdBy, that.createdBy) &&
                Objects.equals(expirationTime, that.expirationTime) &&
                Objects.equals(tags, that.tags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, createdAt, createdBy, expirationTime, tags);
    }

    @Override
    public String toString() {
        return "PolicyMetadata{" +
                "version='" + version + '\'' +
                ", createdAt=" + createdAt +
                ", createdBy='" + createdBy + '\'' +
                ", expirationTime=" + expirationTime +
                ", tags=" + tags +
                '}';
    }

    /**
     * Creates a new builder for {@link PolicyMetadata}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link PolicyMetadata}.
     */
    public static class Builder {
        private String version;
        private Instant createdAt;
        private String createdBy;
        private Instant expirationTime;
        private Map<String, String> tags;

        /**
         * Sets the policy version.
         *
         * @param version the version
         * @return this builder instance
         */
        public Builder version(String version) {
            this.version = version;
            return this;
        }

        /**
         * Sets the creation timestamp.
         *
         * @param createdAt the creation time
         * @return this builder instance
         */
        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        /**
         * Sets the creator identifier.
         *
         * @param createdBy the creator ID
         * @return this builder instance
         */
        public Builder createdBy(String createdBy) {
            this.createdBy = createdBy;
            return this;
        }

        /**
         * Sets the expiration timestamp.
         *
         * @param expirationTime the expiration time
         * @return this builder instance
         */
        public Builder expirationTime(Instant expirationTime) {
            this.expirationTime = expirationTime;
            return this;
        }

        /**
         * Sets the custom tags.
         *
         * @param tags the tags map
         * @return this builder instance
         */
        public Builder tags(Map<String, String> tags) {
            this.tags = tags;
            return this;
        }

        /**
         * Builds the {@link PolicyMetadata}.
         *
         * @return the built metadata
         */
        public PolicyMetadata build() {
            return new PolicyMetadata(version, createdAt, createdBy, expirationTime, tags);
        }
    }
}
