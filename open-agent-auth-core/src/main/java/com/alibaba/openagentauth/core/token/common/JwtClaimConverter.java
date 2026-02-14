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
package com.alibaba.openagentauth.core.token.common;

import com.alibaba.openagentauth.core.model.audit.AuditTrail;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.context.References;
import com.alibaba.openagentauth.core.model.context.TokenAuthorizationContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.nimbusds.jwt.JWTClaimsSet;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for converting model objects to Map representations for JWT claims.
 *
 * <p>This class provides centralized conversion methods to avoid code duplication
 * across multiple JWT generator classes. The conversions handle Instant fields by
 * converting them to String representations to avoid Gson serialization issues.</p>
 *
 * <p><b>NOTE:</b> These conversions are necessary because Gson has issues serializing
 * Instant fields directly. In a production environment, consider using a custom Gson
 * serializer or Jackson with proper Instant handling.</p>
 */
public class JwtClaimConverter {

    /**
     * Converts an AgentIdentity object to a Map for JWT claims.
     *
     * @param agentIdentity the AgentIdentity object
     * @return a Map representation of the AgentIdentity
     */
    public static Map<String, Object> convertAgentIdentityToMap(AgentIdentity agentIdentity) {
        if (agentIdentity == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("version", agentIdentity.getVersion());
        map.put("id", agentIdentity.getId());
        map.put("issuer", agentIdentity.getIssuer());
        map.put("issued_to", agentIdentity.getIssuedTo());

        if (agentIdentity.getIssuedFor() != null) {
            Map<String, Object> issuedForMap = new HashMap<>();
            issuedForMap.put("platform", agentIdentity.getIssuedFor().getPlatform());
            issuedForMap.put("client", agentIdentity.getIssuedFor().getClient());
            issuedForMap.put("client_instance", agentIdentity.getIssuedFor().getClientInstance());
            map.put("issued_for", issuedForMap);
        }

        if (agentIdentity.getIssuanceDate() != null) {
            map.put("issuance_date", agentIdentity.getIssuanceDate().toString());
        }

        if (agentIdentity.getValidFrom() != null) {
            map.put("valid_from", agentIdentity.getValidFrom().toString());
        }

        if (agentIdentity.getExpires() != null) {
            map.put("expires", agentIdentity.getExpires().toString());
        }

        return map;
    }

    /**
     * Converts an Evidence object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization-01, Evidence contains only
     * sourcePromptCredential (a JWT string).
     *
     * @param evidence the Evidence object
     * @return a Map representation of the Evidence
     */
    public static Map<String, Object> convertEvidenceToMap(Evidence evidence) {
        if (evidence == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("source_prompt_credential", evidence.getSourcePromptCredential());

        return map;
    }

    /**
     * Converts an AgentUserBindingProposal object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization-01, this contains:
     * - user_identity_token (JWT string)
     * - agent_workload_token (JWT string)
     * - device_fingerprint (optional string)
     *
     * @param proposal the AgentUserBindingProposal object
     * @return a Map representation of the AgentUserBindingProposal
     */
    public static Map<String, Object> convertAgentUserBindingProposalToMap(AgentUserBindingProposal proposal) {
        if (proposal == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("user_identity_token", proposal.getUserIdentityToken());
        map.put("agent_workload_token", proposal.getAgentWorkloadToken());

        if (proposal.getDeviceFingerprint() != null) {
            map.put("device_fingerprint", proposal.getDeviceFingerprint());
        }

        return map;
    }

    /**
     * Converts an AuditTrail object to a Map for JWT claims.
     *
     * @param auditTrail the AuditTrail object
     * @return a Map representation of the AuditTrail
     */
    public static Map<String, Object> convertAuditTrailToMap(AuditTrail auditTrail) {
        if (auditTrail == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("original_prompt_text", auditTrail.getOriginalPromptText());
        map.put("rendered_operation_text", auditTrail.getRenderedOperationText());
        map.put("semantic_expansion_level", auditTrail.getSemanticExpansionLevel());

        if (auditTrail.getUserAcknowledgeTimestamp() != null) {
            map.put("user_acknowledge_timestamp", auditTrail.getUserAcknowledgeTimestamp().toString());
        }

        map.put("consent_interface_version", auditTrail.getConsentInterfaceVersion());

        return map;
    }

    /**
     * Converts an AgentOperationAuthorization object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization-01, this contains only policy_id.
     *
     * @param authorization the AgentOperationAuthorization object
     * @return a Map representation of the AgentOperationAuthorization
     */
    public static Map<String, Object> convertAuthorizationToMap(AgentOperationAuthorization authorization) {
        if (authorization == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("policy_id", authorization.getPolicyId());

        return map;
    }

    /**
     * Converts an AuthorizationContext object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization-01, this contains at least
     * the renderedText field, which describes the operation in a human-readable format.
     *
     * @param context the AuthorizationContext object
     * @return a Map representation of the AuthorizationContext
     */
    public static Map<String, Object> convertAuthorizationContextToMap(TokenAuthorizationContext context) {
        if (context == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("rendered_text", context.getRenderedText());

        return map;
    }

    /**
     * Converts a Map (from JWT claim) back to an AgentIdentity object.
     *
     * @param agentIdentityClaim the claim object (can be AgentIdentity or Map)
     * @return an AgentIdentity object
     */
    @SuppressWarnings("unchecked")
    public static AgentIdentity convertMapToAgentIdentity(Object agentIdentityClaim) {
        if (agentIdentityClaim instanceof AgentIdentity) {
            return (AgentIdentity) agentIdentityClaim;
        }

        if (!(agentIdentityClaim instanceof Map)) {
            throw new IllegalArgumentException("agent_identity claim must be a Map or AgentIdentity object");
        }

        Map<String, Object> map = (Map<String, Object>) agentIdentityClaim;

        AgentIdentity.IssuedFor issuedFor = null;
        if (map.containsKey("issued_for")) {
            Map<String, Object> issuedForMap = (Map<String, Object>) map.get("issued_for");
            issuedFor = AgentIdentity.IssuedFor.builder()
                    .platform((String) issuedForMap.get("platform"))
                    .client((String) issuedForMap.get("client"))
                    .clientInstance((String) issuedForMap.get("client_instance"))
                    .build();
        }

        return AgentIdentity.builder()
                .version((String) map.get("version"))
                .id((String) map.get("id"))
                .issuer((String) map.get("issuer"))
                .issuedTo((String) map.get("issued_to"))
                .issuedFor(issuedFor)
                .issuanceDate(map.containsKey("issuance_date") ? Instant.parse((String) map.get("issuance_date")) : null)
                .validFrom(map.containsKey("valid_from") ? Instant.parse((String) map.get("valid_from")) : null)
                .expires(map.containsKey("expires") ? Instant.parse((String) map.get("expires")) : null)
                .build();
    }

    /**
     * Converts a Map (from JWT claim) back to an Evidence object.
     * According to draft-liu-agent-operation-authorization-01, Evidence contains only
     * sourcePromptCredential (a JWT string).
     *
     * @param evidenceClaim the claim object (can be Evidence or Map)
     * @return an Evidence object, or null if evidenceClaim is null
     */
    @SuppressWarnings("unchecked")
    public static Evidence convertMapToEvidence(Object evidenceClaim) {
        if (evidenceClaim == null) {
            return null;
        }

        if (evidenceClaim instanceof Evidence) {
            return (Evidence) evidenceClaim;
        }

        if (!(evidenceClaim instanceof Map)) {
            throw new IllegalArgumentException("evidence claim must be a Map or Evidence object");
        }

        Map<String, Object> map = (Map<String, Object>) evidenceClaim;

        return Evidence.builder()
                .sourcePromptCredential((String) map.get("source_prompt_credential"))
                .build();
    }

    /**
     * Converts a Map (from JWT claim) back to an AgentUserBindingProposal object.
     * According to draft-liu-agent-operation-authorization-01, this contains:
     * - user_identity_token (JWT string)
     * - agent_workload_token (JWT string)
     * - device_fingerprint (optional string)
     *
     * @param proposalClaim the claim object (can be AgentUserBindingProposal or Map)
     * @return an AgentUserBindingProposal object
     */
    @SuppressWarnings("unchecked")
    public static AgentUserBindingProposal convertMapToAgentUserBindingProposal(Object proposalClaim) {
        if (proposalClaim instanceof AgentUserBindingProposal) {
            return (AgentUserBindingProposal) proposalClaim;
        }

        if (!(proposalClaim instanceof Map)) {
            throw new IllegalArgumentException("agent_user_binding_proposal claim must be a Map or AgentUserBindingProposal object");
        }

        Map<String, Object> map = (Map<String, Object>) proposalClaim;

        AgentUserBindingProposal.Builder builder = AgentUserBindingProposal.builder()
                .userIdentityToken((String) map.get("user_identity_token"))
                .agentWorkloadToken((String) map.get("agent_workload_token"));

        if (map.containsKey("device_fingerprint")) {
            builder.deviceFingerprint((String) map.get("device_fingerprint"));
        }

        return builder.build();
    }

    /**
     * Converts a Map (from JWT claim) back to an AuditTrail object.
     *
     * @param auditTrailClaim the claim object (can be AuditTrail or Map)
     * @return an AuditTrail object, or null if auditTrailClaim is null
     */
    @SuppressWarnings("unchecked")
    public static AuditTrail convertMapToAuditTrail(Object auditTrailClaim) {
        if (auditTrailClaim == null) {
            return null;
        }

        if (auditTrailClaim instanceof AuditTrail) {
            return (AuditTrail) auditTrailClaim;
        }

        if (!(auditTrailClaim instanceof Map)) {
            throw new IllegalArgumentException("auditTrail claim must be a Map or AuditTrail object");
        }

        Map<String, Object> map = (Map<String, Object>) auditTrailClaim;

        return AuditTrail.builder()
                .originalPromptText((String) map.get("original_prompt_text"))
                .renderedOperationText((String) map.get("rendered_operation_text"))
                .semanticExpansionLevel((String) map.get("semantic_expansion_level"))
                .userAcknowledgeTimestamp((String) map.get("user_acknowledge_timestamp"))
                .consentInterfaceVersion((String) map.get("consent_interface_version"))
                .build();
    }

    /**
     * Converts a Map (from JWT claim) back to an AgentOperationAuthorization object.
     * According to draft-liu-agent-operation-authorization-01, this contains only policy_id.
     *
     * @param authorizationClaim the claim object (can be AgentOperationAuthorization or Map)
     * @return an AgentOperationAuthorization object
     */
    @SuppressWarnings("unchecked")
    public static AgentOperationAuthorization convertMapToAuthorization(Object authorizationClaim) {
        if (authorizationClaim instanceof AgentOperationAuthorization) {
            return (AgentOperationAuthorization) authorizationClaim;
        }

        if (!(authorizationClaim instanceof Map)) {
            throw new IllegalArgumentException("agent_operation_authorization claim must be a Map or AgentOperationAuthorization object");
        }

        Map<String, Object> map = (Map<String, Object>) authorizationClaim;

        return AgentOperationAuthorization.builder()
                .policyId((String) map.get("policy_id"))
                .build();
    }

    /**
     * Converts a Map (from JWT claim) back to an AuthorizationContext object.
     * According to draft-liu-agent-operation-authorization-01, this contains at least
     * the renderedText field.
     *
     * @param contextClaim the claim object (can be AuthorizationContext or Map)
     * @return an AuthorizationContext object, or null if contextClaim is null
     */
    @SuppressWarnings("unchecked")
    public static TokenAuthorizationContext convertMapToAuthorizationContext(Object contextClaim) {
        if (contextClaim == null) {
            return null;
        }

        if (contextClaim instanceof TokenAuthorizationContext) {
            return (TokenAuthorizationContext) contextClaim;
        }

        if (!(contextClaim instanceof Map)) {
            throw new IllegalArgumentException("context claim must be a Map or AuthorizationContext object");
        }

        Map<String, Object> map = (Map<String, Object>) contextClaim;

        return TokenAuthorizationContext.builder()
                .renderedText((String) map.get("rendered_text"))
                .build();
    }

    /**
     * Converts a Map (from JWT claim) back to a Context object.
     *
     * @param contextClaim the claim object (can be Context or Map)
     * @return a Context object
     */
    @SuppressWarnings("unchecked")
    public static OperationRequestContext convertMapToOperationRequestContext(Object contextClaim) {

        if (contextClaim instanceof OperationRequestContext) {
            return (OperationRequestContext) contextClaim;
        }

        if (!(contextClaim instanceof Map)) {
            throw new IllegalArgumentException("context claim must be a Map or Context object");
        }

        Map<String, Object> map = (Map<String, Object>) contextClaim;

        OperationRequestContext.UserContext userContext = null;
        if (map.containsKey("user")) {
            Map<String, Object> userMap = (Map<String, Object>) map.get("user");
            userContext = OperationRequestContext.UserContext.builder()
                    .id((String) userMap.get("id"))
                    .build();
        }

        OperationRequestContext.AgentContext agentContext = null;
        if (map.containsKey("agent")) {
            Map<String, Object> agentMap = (Map<String, Object>) map.get("agent");
            agentContext = OperationRequestContext.AgentContext.builder()
                    .instance((String) agentMap.get("instance"))
                    .platform((String) agentMap.get("platform"))
                    .client((String) agentMap.get("client"))
                    .build();
        }

        return OperationRequestContext.builder()
                .channel((String) map.get("channel"))
                .deviceFingerprint((String) map.get("device_fingerprint"))
                .language((String) map.get("language"))
                .user(userContext)
                .agent(agentContext)
                .build();
    }

    /**
     * Converts a References object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization, this contains:
     * - relatedProposalId (optional string)
     *
     * @param references the References object
     * @return a Map representation of the References
     */
    public static Map<String, Object> convertReferencesToMap(References references) {
        if (references == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("related_proposal_id", references.getRelatedProposalId());

        return map;
    }

    /**
     * Converts a Map (from JWT claim) back to a References object.
     *
     * @param referencesClaim the claim object (can be References or Map)
     * @return a References object, or null if referencesClaim is null
     */
    @SuppressWarnings("unchecked")
    public static References convertMapToReferences(Object referencesClaim) {
        if (referencesClaim == null) {
            return null;
        }

        if (referencesClaim instanceof References) {
            return (References) referencesClaim;
        }

        if (!(referencesClaim instanceof Map)) {
            throw new IllegalArgumentException("references claim must be a Map or References object");
        }

        Map<String, Object> map = (Map<String, Object>) referencesClaim;

        return References.builder()
                .relatedProposalId((String) map.get("related_proposal_id"))
                .build();
    }

    /**
     * Converts a DelegationChain object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization, this contains:
     * - delegatorJti (required string)
     * - delegatorAgentIdentity (required AgentIdentity)
     * - delegationTimestamp (required Instant)
     * - operationSummary (optional string)
     * - asSignature (required string)
     *
     * @param delegationChain the DelegationChain object
     * @return a Map representation of the DelegationChain
     */
    public static Map<String, Object> convertDelegationChainToMap(DelegationChain delegationChain) {
        if (delegationChain == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("delegator_jti", delegationChain.getDelegatorJti());
        map.put("delegator_agent_identity", convertAgentIdentityToMap(delegationChain.getDelegatorAgentIdentity()));

        if (delegationChain.getDelegationTimestamp() != null) {
            map.put("delegation_timestamp", delegationChain.getDelegationTimestamp().toString());
        }

        map.put("operation_summary", delegationChain.getOperationSummary());
        map.put("as_signature", delegationChain.getAsSignature());

        return map;
    }

    /**
     * Converts a Map (from JWT claim) back to a DelegationChain object.
     *
     * @param delegationChainClaim the claim object (can be DelegationChain or Map)
     * @return a DelegationChain object
     */
    @SuppressWarnings("unchecked")
    public static DelegationChain convertMapToDelegationChain(Object delegationChainClaim) {
        if (delegationChainClaim instanceof DelegationChain) {
            return (DelegationChain) delegationChainClaim;
        }

        if (!(delegationChainClaim instanceof Map)) {
            throw new IllegalArgumentException("delegation_chain claim must be a Map or DelegationChain object");
        }

        Map<String, Object> map = (Map<String, Object>) delegationChainClaim;

        AgentIdentity delegatorAgentIdentity = null;
        if (map.containsKey("delegator_agent_identity")) {
            delegatorAgentIdentity = convertMapToAgentIdentity(map.get("delegator_agent_identity"));
        }

        return DelegationChain.builder()
                .delegatorJti((String) map.get("delegator_jti"))
                .delegatorAgentIdentity(delegatorAgentIdentity)
                .delegationTimestamp(map.containsKey("delegation_timestamp") ?
                    Instant.parse((String) map.get("delegation_timestamp")) : null)
                .operationSummary((String) map.get("operation_summary"))
                .asSignature((String) map.get("as_signature"))
                .build();
    }

    /**
     * Converts a list of DelegationChain objects to a List of Maps for JWT claims.
     *
     * @param delegationChainList the list of DelegationChain objects
     * @return a List of Map representations of the DelegationChain objects
     */
    public static List<Map<String, Object>> convertDelegationChainListToMap(List<DelegationChain> delegationChainList) {
        if (delegationChainList == null || delegationChainList.isEmpty()) {
            return new ArrayList<>();
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (DelegationChain delegationChain : delegationChainList) {
            result.add(convertDelegationChainToMap(delegationChain));
        }

        return result;
    }

    /**
     * Converts a List of Maps (from JWT claim) back to a List of DelegationChain objects.
     *
     * @param delegationChainListClaim the claim object (can be List<DelegationChain> or List<Map>)
     * @return a List of DelegationChain objects, or null if delegationChainListClaim is null
     */
    @SuppressWarnings("unchecked")
    public static List<DelegationChain> convertMapToDelegationChainList(Object delegationChainListClaim) {
        if (delegationChainListClaim == null) {
            return null;
        }

        if (delegationChainListClaim instanceof List) {
            List<?> list = (List<?>) delegationChainListClaim;
            if (list.isEmpty()) {
                return new ArrayList<>();
            }

            // Check if it's already a list of DelegationChain objects
            if (list.get(0) instanceof DelegationChain) {
                return (List<DelegationChain>) delegationChainListClaim;
            }

            // Convert from Map list
            List<DelegationChain> result = new ArrayList<>();
            for (Object item : list) {
                result.add(convertMapToDelegationChain(item));
            }
            return result;
        }

        throw new IllegalArgumentException("delegation_chain claim must be a List");
    }

    /**
     * Converts an OperationRequestContext object to a Map for JWT claims.
     * According to draft-liu-agent-operation-authorization-01, this contains:
     * - channel (optional string)
     * - deviceFingerprint (optional string)
     * - language (optional string)
     * - user (optional UserContext)
     * - agent (optional AgentContext)
     *
     * @param context the OperationRequestContext object
     * @return a Map representation of the OperationRequestContext
     */
    public static Map<String, Object> convertOperationRequestContextToMap(OperationRequestContext context) {
        if (context == null) {
            return new HashMap<>();
        }

        Map<String, Object> map = new HashMap<>();
        map.put("channel", context.getChannel());
        map.put("device_fingerprint", context.getDeviceFingerprint());
        map.put("language", context.getLanguage());

        if (context.getUser() != null) {
            Map<String, Object> userMap = new HashMap<>();
            userMap.put("id", context.getUser().getId());
            map.put("user", userMap);
        }

        if (context.getAgent() != null) {
            Map<String, Object> agentMap = new HashMap<>();
            agentMap.put("instance", context.getAgent().getInstance());
            agentMap.put("platform", context.getAgent().getPlatform());
            agentMap.put("client", context.getAgent().getClient());
            map.put("agent", agentMap);
        }

        return map;
    }

    /**
     * Converts a JWTClaimsSet to an AgentOperationAuthToken.Claims object.
     * This method extracts all claims from the JWTClaimsSet and builds an AOAT Claims object.
     *
     * @param claimsSet the JWT claims set
     * @return an AgentOperationAuthToken.Claims object
     */
    public static AgentOperationAuthToken.Claims convertJwtClaimsSetToAoatClaims(JWTClaimsSet claimsSet) {

        // Extract claims
        Object evidenceClaim = claimsSet.getClaim("evidence");
        Object agentIdentityClaim = claimsSet.getClaim("agent_identity");
        Object authorizationClaim = claimsSet.getClaim("agent_operation_authorization");
        Object contextClaim = claimsSet.getClaim("context");
        Object auditTrailClaim = claimsSet.getClaim("audit_trail");
        Object referencesClaim = claimsSet.getClaim("references");
        Object delegationChainClaim = claimsSet.getClaim("delegation_chain");

        // Convert audience from List<String> to String (take first if multiple)
        String audience = null;
        List<String> audiences = claimsSet.getAudience();
        if (audiences != null && !audiences.isEmpty()) {
            audience = audiences.get(0);
        }

        // Convert Date to Instant
        Instant issuedAt = null;
        if (claimsSet.getIssueTime() != null) {
            issuedAt = claimsSet.getIssueTime().toInstant();
        }

        Instant expirationTime = null;
        if (claimsSet.getExpirationTime() != null) {
            expirationTime = claimsSet.getExpirationTime().toInstant();
        }

        return AgentOperationAuthToken.Claims.builder()
                .issuer(claimsSet.getIssuer())
                .subject(claimsSet.getSubject())
                .audience(audience)
                .issuedAt(issuedAt)
                .expirationTime(expirationTime)
                .jwtId(claimsSet.getJWTID())
                .evidence(convertMapToEvidence(evidenceClaim))
                .agentIdentity(convertMapToAgentIdentity(agentIdentityClaim))
                .authorization(convertMapToAuthorization(authorizationClaim))
                .context(convertMapToAuthorizationContext(contextClaim))
                .auditTrail(convertMapToAuditTrail(auditTrailClaim))
                .references(convertMapToReferences(referencesClaim))
                .delegationChain(convertMapToDelegationChainList(delegationChainClaim))
                .build();
    }

}