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
package com.alibaba.openagentauth.core.model.evidence;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a cryptographic proof for a Verifiable Credential.
 * This proof provides additional verification information about the credential,
 * including the proof type, creation timestamp, and verification method.
 * <p>
 * According to draft-liu-agent-operation-authorization-01 Section 4.2, the proof
 * contains the following fields:
 * </p>
 * <table border="1">
 *   <tr><th>Field</th><th>Description</th><th>Status</th></tr>
 *   <tr><td>type</td><td>Type - the proof type</td><td>REQUIRED</td></tr>
 *   <tr><td>created</td><td>Created - the creation timestamp of the proof</td><td>REQUIRED</td></tr>
 *   <tr><td>verificationMethod</td><td>Verification Method - the verification method used</td><td>REQUIRED</td></tr>
 * </table>
 * <p>
 * The proof is used to cryptographically verify the authenticity and integrity
 * of the Verifiable Credential.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/#proofs-signatures">W3C Verifiable Credentials Data Model - Proofs</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Proof {

    @JsonProperty("type")
    private final String type;

    @JsonProperty("created")
    private final String created;

    @JsonProperty("verificationMethod")
    private final String verificationMethod;

    /**
     * Private constructor for Builder pattern.
     */
    private Proof(Builder builder) {
        this.type = builder.type;
        this.created = builder.created;
        this.verificationMethod = builder.verificationMethod;
    }

    /**
     * JSON creator for Jackson deserialization.
     */
    @com.fasterxml.jackson.annotation.JsonCreator
    private Proof(
            @com.fasterxml.jackson.annotation.JsonProperty("type") String type,
            @com.fasterxml.jackson.annotation.JsonProperty("created") String created,
            @com.fasterxml.jackson.annotation.JsonProperty("verificationMethod") String verificationMethod) {
        this.type = type;
        this.created = created;
        this.verificationMethod = verificationMethod;
    }

    /**
     * Type field.
     * <p>
     * Identifies the type of the cryptographic proof.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED.
     * Common values include "JwtProof2020" or other proof types defined in W3C VC Data Model.
     * </p>
     *
     * @return the proof type
     */
    public String getType() {
        return type;
    }

    /**
     * Created field.
     * <p>
     * Identifies the creation timestamp of the proof.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED.
     * The value MUST conform to ISO 8601 UTC format.
     * </p>
     *
     * @return the creation timestamp
     */
    public String getCreated() {
        return created;
    }

    /**
     * Verification Method field.
     * <p>
     * Identifies the verification method used to create the proof.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED.
     * This typically references a key or cryptographic method (e.g., a DID URL or key ID).
     * </p>
     *
     * @return the verification method
     */
    public String getVerificationMethod() {
        return verificationMethod;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Proof proof = (Proof) o;
        return Objects.equals(type, proof.type)
                && Objects.equals(created, proof.created)
                && Objects.equals(verificationMethod, proof.verificationMethod);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, created, verificationMethod);
    }

    @Override
    public String toString() {
        return "Proof{" +
                "type='" + type + '\'' +
                ", created='" + created + '\'' +
                ", verificationMethod='" + verificationMethod + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link Proof}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link Proof}.
     */
    public static class Builder {
        private String type = "JwtProof2020";
        private String created;
        private String verificationMethod;

        /**
         * Sets the proof type.
         *
         * @param type the proof type
         * @return this builder instance
         */
        public Builder type(String type) {
            this.type = type;
            return this;
        }

        /**
         * Sets the creation timestamp.
         *
         * @param created the creation timestamp
         * @return this builder instance
         */
        public Builder created(String created) {
            this.created = created;
            return this;
        }

        /**
         * Sets the creation timestamp from an Instant.
         *
         * @param created the creation timestamp
         * @return this builder instance
         */
        public Builder created(Instant created) {
            this.created = created.toString();
            return this;
        }

        /**
         * Sets the verification method.
         *
         * @param verificationMethod the verification method
         * @return this builder instance
         */
        public Builder verificationMethod(String verificationMethod) {
            this.verificationMethod = verificationMethod;
            return this;
        }

        /**
         * Builds the {@link Proof}.
         *
         * @return the built proof
         */
        public Proof build() {
            return new Proof(this);
        }
    }
}
