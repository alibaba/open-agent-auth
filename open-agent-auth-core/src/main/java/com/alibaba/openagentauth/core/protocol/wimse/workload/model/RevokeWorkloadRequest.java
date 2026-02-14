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
package com.alibaba.openagentauth.core.protocol.wimse.workload.model;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Request for revoking a workload by workload ID.
 * <p>
 * This class encapsulates the parameters needed to revoke a specific agent workload.
 * Revoking a workload invalidates any tokens issued for it and prevents further
 * token issuance using that workload.
 * </p>
 * <p>
 * According to WIMSE protocol, workload revocation is an important security mechanism
 * that allows administrators or security systems to immediately invalidate compromised
 * or no longer needed workloads. This is particularly important in scenarios where:
 * </p>
 * <ul>
 *   <li>A security incident has been detected</li>
 *   <li>The agent operation has completed</li>
 *   <li>User authorization has been revoked</li>
 *   <li>The workload has expired</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RevokeWorkloadRequest {

    /**
     * The WIMSE workload identifier.
     * <p>
     * This field is REQUIRED and uniquely identifies the workload to be revoked.
     * Once revoked, the workload cannot be used to issue new tokens, and any
     * existing tokens issued for this workload should be considered invalid.
     * </p>
     * <p>
     * The workload ID format is defined by the WIMSE protocol and should be
     * treated as an opaque string.
     * </p>
     */
    @JsonProperty("workloadId")
    private final String workloadId;

    /**
     * Constructor for Jackson deserialization.
     *
     * @param workloadId the WIMSE workload identifier
     */
    @JsonCreator
    public RevokeWorkloadRequest(@JsonProperty("workloadId") String workloadId) {
        this.workloadId = workloadId;
    }

    /**
     * Constructor for builder pattern.
     *
     * @param builder the builder instance
     */
    private RevokeWorkloadRequest(Builder builder) {
        this.workloadId = builder.workloadId;
    }

    /**
     * Gets the WIMSE workload identifier.
     *
     * @return the workload identifier
     */
    public String getWorkloadId() {
        return workloadId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RevokeWorkloadRequest that = (RevokeWorkloadRequest) o;
        return Objects.equals(workloadId, that.workloadId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(workloadId);
    }

    @Override
    public String toString() {
        return "RevokeWorkloadRequest{" +
                "workloadId='" + workloadId + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link RevokeWorkloadRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link RevokeWorkloadRequest}.
     * <p>
     * This builder provides a fluent API for constructing RevokeWorkloadRequest instances
     * with proper validation of required fields.
     * </p>
     */
    public static class Builder {

        /**
         * The WIMSE workload identifier.
         */
        private String workloadId;

        /**
         * Sets the WIMSE workload identifier.
         * <p>
         * This field is REQUIRED and must uniquely identify the workload to be revoked.
         * </p>
         *
         * @param workloadId the workload identifier
         * @return this builder instance
         */
        public Builder workloadId(String workloadId) {
            this.workloadId = workloadId;
            return this;
        }

        /**
         * Builds the {@link RevokeWorkloadRequest}.
         * <p>
         * This method validates that all required fields are present before
         * constructing the request object.
         * </p>
         *
         * @return the built revoke workload request
         * @throws IllegalArgumentException if any required field is null or empty
         */
        public RevokeWorkloadRequest build() {
            if (ValidationUtils.isNullOrEmpty(workloadId)) {
                throw new IllegalArgumentException("Workload ID is required");
            }
            return new RevokeWorkloadRequest(this);
        }
    }
}
