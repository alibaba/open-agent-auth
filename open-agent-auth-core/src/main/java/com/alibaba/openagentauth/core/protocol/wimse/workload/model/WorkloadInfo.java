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

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Information about a WIMSE workload.
 * <p>
 * This class encapsulates metadata about a workload as defined in the WIMSE protocol
 * (draft-ietf-wimse-workload-creds). It represents a workload identity that can be
 * used for authentication and authorization in distributed systems.
 * </p>
 * <p>
 * <b>Protocol Context:</b></p>
 * <ul>
 *   <li>Workload is a core concept in WIMSE protocol</li>
 *   <li>Each workload has a unique identifier scoped within a trust domain</li>
 *   <li>Workloads have a lifecycle (creation, expiration, revocation)</li>
 *   <li>Workloads contain a key pair for cryptographic operations</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkloadInfo {
    
    /**
     * The unique workload identifier.
     * <p>
     * This identifier is scoped within the trust domain and should be unique.
     * Common formats include UUIDs or structured identifiers like SPIFFE IDs.
     * </p>
     */
    @JsonProperty("workloadId")
    private final String workloadId;
    
    /**
     * The user ID this workload is bound to.
     * <p>
     * This represents the user identity that owns or created this workload.
     * Used for traceability and authorization decisions.
     * </p>
     */
    @JsonProperty("userId")
    private final String userId;
    
    /**
     * The trust domain this workload belongs to.
     * <p>
     * REQUIRED by WIMSE specification.
     * The trust domain defines the scope of trust for this workload identity.
     * </p>
     * <p>
     * <b>Format:</b> {@code wimse://<domain>}
     * </p>
     * <p>
     * <b>Example:</b> {@code wimse://example.com}
     * </p>
     * <p>
     * The trust domain must be tied to an authorized issuer's cryptographic trust anchor
     * through a mechanism such as JWKS or X.509 certificate chain.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch-06#section-3.2">WIMSE Architecture Section 3.2</a>
     */
    @JsonProperty("trustDomain")
    private final String trustDomain;
    
    /**
     * The issuer of this workload identity.
     * <p>
     * OPTIONAL but RECOMMENDED by WIMSE specification.
     * Identifies the entity (e.g., WIMSE IDP) that issued this workload identity.
     * </p>
     * <p>
     * When present, it typically contains the URL of the issuer.
     * This is used for key distribution and trust establishment.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
     */
    @JsonProperty("issuer")
    private final String issuer;
    
    /**
     * The public key in JWK format.
     * <p>
     * This public key is used to verify signatures created by the workload.
     * It is included in the Workload Identity Token (WIT) confirmation claim.
     * </p>
     */
    @JsonProperty("publicKey")
    private final String publicKey;
    
    /**
     * The creation timestamp.
     * <p>
     * The time when this workload was created.
     * </p>
     */
    @JsonProperty("createdAt")
    private final Instant createdAt;
    
    /**
     * The expiration timestamp.
     * <p>
     * The time when this workload expires. After this time, the workload
     * should be considered invalid and any tokens issued for it should be rejected.
     * </p>
     */
    @JsonProperty("expiresAt")
    private final Instant expiresAt;
    
    /**
     * The workload status.
     * <p>
     * Common values include "active", "revoked", "expired".
     * </p>
     */
    @JsonProperty("status")
    private final String status;
    
    /**
     * The private key in JWK format (internal use only).
     * <p>
     * This field is not serialized to JSON as it should never be exposed.
     * It is used internally for signing operations.
     * </p>
     */
    @JsonProperty("privateKey")
    private transient final String privateKey;
    
    /**
     * The operation request context.
     * <p>
     * This field contains contextual information about the operation request,
     * including user and agent identity attributes, device characteristics,
     * channel, and locale for policy evaluation.
     * </p>
     */
    @JsonProperty("context")
    private final OperationRequestContext context;
    
    /**
     * Additional workload metadata.
     * <p>
     * This field contains additional metadata about the workload, such as
     * workload unique key for indexing and lookup purposes.
     * </p>
     */
    @JsonProperty("metadata")
    private final Map<String, Object> metadata;
    
    /**
     * Constructor for JSON deserialization.
     * <p>
     * This constructor is used by Jackson when deserializing from JSON.
     * It does not include the private key for security reasons.
     * </p>
     */
    @JsonCreator
    public WorkloadInfo(
            @JsonProperty("workloadId") String workloadId,
            @JsonProperty("userId") String userId,
            @JsonProperty("trustDomain") String trustDomain,
            @JsonProperty("issuer") String issuer,
            @JsonProperty("publicKey") String publicKey,
            @JsonProperty("createdAt") Instant createdAt,
            @JsonProperty("expiresAt") Instant expiresAt,
            @JsonProperty("status") String status,
            @JsonProperty("context") OperationRequestContext context,
            @JsonProperty("metadata") Map<String, Object> metadata
    ) {
        this.workloadId = workloadId;
        this.userId = userId;
        this.trustDomain = trustDomain;
        this.issuer = issuer;
        this.publicKey = publicKey;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.status = status;
        this.privateKey = null;
        this.context = context;
        this.metadata = metadata;
    }
    
    /**
     * Full constructor including private key.
     * <p>
     * This constructor is used internally when creating new workloads.
     * The private key is marked as transient to prevent JSON serialization.
     * </p>
     */
    public WorkloadInfo(
            String workloadId,
            String userId,
            String trustDomain,
            String issuer,
            String publicKey,
            String privateKey,
            Instant createdAt,
            Instant expiresAt,
            String status,
            OperationRequestContext context,
            Map<String, Object> metadata
    ) {
        this.workloadId = workloadId;
        this.userId = userId;
        this.trustDomain = trustDomain;
        this.issuer = issuer;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.status = status;
        this.context = context;
        this.metadata = metadata;
    }
    
    // Getters
    
    public String getWorkloadId() { 
        return workloadId; 
    }
    
    public String getUserId() { 
        return userId; 
    }
    
    public String getTrustDomain() { 
        return trustDomain; 
    }
    
    public String getIssuer() { 
        return issuer; 
    }
    
    public String getPublicKey() { 
        return publicKey; 
    }
    
    public String getPrivateKey() { 
        return privateKey; 
    }
    
    public Instant getCreatedAt() { 
        return createdAt; 
    }
    
    public Instant getExpiresAt() { 
        return expiresAt; 
    }
    
    public String getStatus() { 
        return status; 
    }
    
    public OperationRequestContext getContext() {
        return context;
    }
    
    public Map<String, Object> getMetadata() {
        return metadata;
    }
    
    /**
     * Checks if this workload is expired.
     *
     * @return true if expired, false otherwise
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
    
    /**
     * Checks if this workload is active.
     *
     * @return true if active, false otherwise
     */
    public boolean isActive() {
        return "active".equalsIgnoreCase(status) && !isExpired();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WorkloadInfo that = (WorkloadInfo) o;
        return Objects.equals(workloadId, that.workloadId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(workloadId);
    }
    
    @Override
    public String toString() {
        return "WorkloadInfo{" +
                "workloadId='" + workloadId + '\'' +
                ", userId='" + userId + '\'' +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", status='" + status + '\'' +
                '}';
    }
}
