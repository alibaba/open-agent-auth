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
 * Represents a JWT-based Verifiable Credential (JWT-VC) for evidence.
 * <p>
 * This credential captures the user's original natural-language input and provides
 * cryptographic proof of its authenticity. It follows the W3C Verifiable Credentials
 * Data Model and includes standard claims such as issuer, subject, issuance date,
 * expiration date, and a cryptographic proof.
 * <p>
 * The credential is used in the Agent Operation Authorization framework to establish
 * a verifiable chain of evidence from the user's original intent to the agent's
 * authorized operations.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization-01/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerifiableCredential {

    @JsonProperty("jti")
    private final String jti;

    @JsonProperty("iss")
    private final String iss;

    @JsonProperty("sub")
    private final String sub;

    @JsonProperty("iat")
    private final Long iat;

    @JsonProperty("exp")
    private final Long exp;

    @JsonProperty("type")
    private final String type;

    @JsonProperty("credentialSubject")
    private final UserInputEvidence credentialSubject;

    @JsonProperty("issuer")
    private final String issuer;

    @JsonProperty("issuanceDate")
    private final String issuanceDate;

    @JsonProperty("expirationDate")
    private final String expirationDate;

    @JsonProperty("proof")
    private final Proof proof;

    private VerifiableCredential(Builder builder) {
        this.jti = builder.jti;
        this.iss = builder.iss;
        this.sub = builder.sub;
        this.iat = builder.iat;
        this.exp = builder.exp;
        this.type = builder.type;
        this.credentialSubject = builder.credentialSubject;
        this.issuer = builder.issuer;
        this.issuanceDate = builder.issuanceDate;
        this.expirationDate = builder.expirationDate;
        this.proof = builder.proof;
    }

    /**
     * JWT ID claim (jti).
     * <p>
     * Provides a unique identifier for the credential.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is OPTIONAL.
     * The identifier value MUST be assigned in a manner that ensures that there is a negligible
     * probability that the same value will be accidentally assigned to a different credential.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 Section 4.1.7</a>
     * @return the JWT ID
     */
    public String getJti() {
        return jti;
    }

    /**
     * Issuer claim (iss).
     * <p>
     * Identifies the principal that issued the credential.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 Section 4.1.1</a>
     * @return the issuer
     */
    public String getIss() {
        return iss;
    }

    /**
     * Subject claim (sub).
     * <p>
     * Identifies the principal that is the subject of the credential.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 Section 4.1.2</a>
     * @return the subject
     */
    public String getSub() {
        return sub;
    }

    /**
     * Issued At claim (iat).
     * <p>
     * Identifies the time at which the credential was issued.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * The value MUST be a NumericDate (seconds since Epoch, 1970-01-01T00:00:00Z UTC).
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</a>
     * @return the issued at time
     */
    public Long getIat() {
        return iat;
    }

    /**
     * Expiration Time claim (exp).
     * <p>
     * Identifies the expiration time on or after which the credential MUST NOT be accepted for processing.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * The value MUST be a NumericDate (seconds since Epoch, 1970-01-01T00:00:00Z UTC).
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</a>
     * @return the expiration time
     */
    public Long getExp() {
        return exp;
    }

    /**
     * Type claim.
     * <p>
     * Identifies the type of the credential.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * </p>
     *
     * @return the type
     */
    public String getType() {
        return type;
    }

    /**
     * Credential Subject claim.
     * <p>
     * Contains the user input evidence.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * </p>
     *
     * @return the credential subject
     */
    public UserInputEvidence getCredentialSubject() {
        return credentialSubject;
    }

    /**
     * Issuer claim.
     * <p>
     * Identifies the issuer of the credential.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * </p>
     *
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Issuance Date claim.
     * <p>
     * Identifies the date when the credential was issued.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * The value MUST conform to ISO 8601 UTC format.
     * </p>
     *
     * @return the issuance date
     */
    public String getIssuanceDate() {
        return issuanceDate;
    }

    /**
     * Expiration Date claim.
     * <p>
     * Identifies the date when the credential expires.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * The value MUST conform to ISO 8601 UTC format.
     * </p>
     *
     * @return the expiration date
     */
    public String getExpirationDate() {
        return expirationDate;
    }

    /**
     * Proof claim.
     * <p>
     * Contains the cryptographic proof of the credential.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this claim is REQUIRED.
     * </p>
     *
     * @return the proof
     */
    public Proof getProof() {
        return proof;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerifiableCredential that = (VerifiableCredential) o;
        return Objects.equals(jti, that.jti)
                && Objects.equals(iss, that.iss)
                && Objects.equals(sub, that.sub)
                && Objects.equals(iat, that.iat)
                && Objects.equals(exp, that.exp)
                && Objects.equals(type, that.type)
                && Objects.equals(credentialSubject, that.credentialSubject)
                && Objects.equals(issuer, that.issuer)
                && Objects.equals(issuanceDate, that.issuanceDate)
                && Objects.equals(expirationDate, that.expirationDate)
                && Objects.equals(proof, that.proof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jti, iss, sub, iat, exp, type, credentialSubject, issuer, issuanceDate, expirationDate, proof);
    }

    @Override
    public String toString() {
        return "VerifiableCredential{" +
                "jti='" + jti + '\'' +
                ", iss='" + iss + '\'' +
                ", sub='" + sub + '\'' +
                ", iat=" + iat +
                ", exp=" + exp +
                ", type='" + type + '\'' +
                ", credentialSubject=" + credentialSubject +
                ", issuer='" + issuer + '\'' +
                ", issuanceDate='" + issuanceDate + '\'' +
                ", expirationDate='" + expirationDate + '\'' +
                ", proof=" + proof +
                '}';
    }

    /**
     * Creates a new builder for {@link VerifiableCredential}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link VerifiableCredential}.
     */
    public static class Builder {
        private String jti;
        private String iss;
        private String sub;
        private Long iat;
        private Long exp;
        private String type;
        private UserInputEvidence credentialSubject;
        private String issuer;
        private String issuanceDate;
        private String expirationDate;
        private Proof proof;

        /**
         * Sets the JWT ID.
         *
         * @param jti the JWT ID
         * @return this builder instance
         */
        public Builder jti(String jti) {
            this.jti = jti;
            return this;
        }

        /**
         * Sets the issuer.
         *
         * @param iss the issuer
         * @return this builder instance
         */
        public Builder iss(String iss) {
            this.iss = iss;
            return this;
        }

        /**
         * Sets the subject.
         *
         * @param sub the subject
         * @return this builder instance
         */
        public Builder sub(String sub) {
            this.sub = sub;
            return this;
        }

        /**
         * Sets the issued at time.
         *
         * @param iat the issued at time
         * @return this builder instance
         */
        public Builder iat(Long iat) {
            this.iat = iat;
            return this;
        }

        /**
         * Sets the issued at time from an Instant.
         *
         * @param iat the issued at time
         * @return this builder instance
         */
        public Builder iat(Instant iat) {
            this.iat = iat.getEpochSecond();
            return this;
        }

        /**
         * Sets the expiration time.
         *
         * @param exp the expiration time
         * @return this builder instance
         */
        public Builder exp(Long exp) {
            this.exp = exp;
            return this;
        }

        /**
         * Sets the expiration time from an Instant.
         *
         * @param exp the expiration time
         * @return this builder instance
         */
        public Builder exp(Instant exp) {
            this.exp = exp.getEpochSecond();
            return this;
        }

        /**
         * Sets the credential type.
         *
         * @param type the type
         * @return this builder instance
         */
        public Builder type(String type) {
            this.type = type;
            return this;
        }

        /**
         * Sets the credential subject.
         *
         * @param credentialSubject the credential subject
         * @return this builder instance
         */
        public Builder credentialSubject(UserInputEvidence credentialSubject) {
            this.credentialSubject = credentialSubject;
            return this;
        }

        /**
         * Sets the issuer.
         *
         * @param issuer the issuer
         * @return this builder instance
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Sets the issuance date.
         *
         * @param issuanceDate the issuance date
         * @return this builder instance
         */
        public Builder issuanceDate(String issuanceDate) {
            this.issuanceDate = issuanceDate;
            return this;
        }

        /**
         * Sets the issuance date from an Instant.
         *
         * @param issuanceDate the issuance date
         * @return this builder instance
         */
        public Builder issuanceDate(Instant issuanceDate) {
            this.issuanceDate = issuanceDate.toString();
            return this;
        }

        /**
         * Sets the expiration date.
         *
         * @param expirationDate the expiration date
         * @return this builder instance
         */
        public Builder expirationDate(String expirationDate) {
            this.expirationDate = expirationDate;
            return this;
        }

        /**
         * Sets the expiration date from an Instant.
         *
         * @param expirationDate the expiration date
         * @return this builder instance
         */
        public Builder expirationDate(Instant expirationDate) {
            this.expirationDate = expirationDate.toString();
            return this;
        }

        /**
         * Sets the cryptographic proof.
         *
         * @param proof the proof
         * @return this builder instance
         */
        public Builder proof(Proof proof) {
            this.proof = proof;
            return this;
        }

        /**
         * Builds the {@link VerifiableCredential}.
         *
         * @return the built credential
         */
        public VerifiableCredential build() {
            return new VerifiableCredential(this);
        }
    }
}