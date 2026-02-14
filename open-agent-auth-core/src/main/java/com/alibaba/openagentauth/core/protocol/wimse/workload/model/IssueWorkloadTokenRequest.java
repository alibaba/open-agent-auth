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
 * Request for issuing a Workload Identity Token (WIT) for an existing workload.
 * <p>
 * This class encapsulates the parameters needed to issue a WIT for a specific
 * workload using its WIMSE workload identifier. The WIT contains both standard
 * WIT claims and agent-specific identity claims.
 * </p>
 * <p>
 * According to the WIMSE protocol and the Agent Operation Authorization draft,
 * the WIT issued by this request includes:
 * </p>
 * <ul>
 *   <li><b>Standard WIT Claims:</b> Subject, issuer, audience, expiration, etc.</li>
 *   <li><b>Agent Identity Claims:</b> Agent ID, agent type, operation context</li>
 *   <li><b>User Binding Claims:</b> User identity binding for traceability</li>
 * </ul>
 * <p>
 * This request is used when the client already has a workload ID and wants to
 * obtain a WIT without going through the full workload creation process.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">draft-ietf-wimse-workload-creds</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssueWorkloadTokenRequest {

    /**
     * The WIMSE workload identifier.
     * <p>
     * This field is REQUIRED and uniquely identifies the workload for which
     * the WIT should be issued. The workload must exist and not be expired.
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
    public IssueWorkloadTokenRequest(@JsonProperty("workloadId") String workloadId) {
        this.workloadId = workloadId;
    }

    /**
     * Constructor for builder pattern.
     *
     * @param builder the builder instance
     */
    private IssueWorkloadTokenRequest(Builder builder) {
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
        IssueWorkloadTokenRequest that = (IssueWorkloadTokenRequest) o;
        return Objects.equals(workloadId, that.workloadId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(workloadId);
    }

    @Override
    public String toString() {
        return "IssueWorkloadTokenRequest{" +
                "workloadId='" + workloadId + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link IssueWorkloadTokenRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link IssueWorkloadTokenRequest}.
     * <p>
     * This builder provides a fluent API for constructing IssueWorkloadTokenRequest
     * instances with proper validation of required fields.
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
         * This field is REQUIRED and must uniquely identify the workload for which
         * the WIT should be issued.
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
         * Builds the {@link IssueWorkloadTokenRequest}.
         * <p>
         * This method validates that all required fields are present before
         * constructing the request object.
         * </p>
         *
         * @return the built issue workload token request
         * @throws IllegalArgumentException if any required field is null or empty
         */
        public IssueWorkloadTokenRequest build() {
            if (ValidationUtils.isNullOrEmpty(workloadId)) {
                throw new IllegalArgumentException("Workload ID is required");
            }
            return new IssueWorkloadTokenRequest(this);
        }
    }
}
