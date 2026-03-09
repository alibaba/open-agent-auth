---
sep: "0001"
title: "Agent Identity Profile (AIP): A Structured Identity Metadata Framework for AI Agents"
status: Draft
type: Standards Track
created: 2026-03-07
updated: 2026-03-09
authors:
  - Open Agent Auth Contributors
requires: []
replaces: null
superseded-by: null
tracking-issue: "https://github.com/alibaba/open-agent-auth/issues/16"
---

# SEP-0001: Agent Identity Profile (AIP)

## A Structured Identity Metadata Framework for AI Agents

### Abstract

This document defines the Agent Identity Profile (AIP), a structured
identity metadata framework for AI agents operating within and across
trust domains.  AIP provides a standardized JSON-based document format
that describes an agent's identity attributes, owner bindings,
capability declarations, integrity assurances, governance policies,
trust posture, credential lifecycle state, and observability
configuration.

AIP is designed as a complementary layer within the existing protocol
ecosystem.  It bridges the gap between workload-level credential
systems (WIMSE WIT/WPT), user-level authentication protocols
(OpenID Connect, OIDC-A), and operation-level authorization frameworks
(AOAT) by providing a unified, cacheable, and verifiable identity
metadata document that can be referenced throughout an agent's
lifecycle.

This specification defines the AIP data model, the document
partitioning strategy (AIP-Static and AIP-Dynamic), the lifecycle
state machine, the trust posture model, the discovery and resolution
protocol, the delegation chain constraints for multi-agent scenarios,
the integrity verification model, the cross-domain projection
mechanism for federated trust environments, and the conformance
requirements for implementers.

### Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering
Task Force (IETF).  Note that other groups MAY also distribute
working documents as Internet-Drafts.  The list of current Internet-
Drafts is at https://datatracker.ietf.org/drafts/current/.

Internet-Drafts are draft documents valid for a maximum of six months
and MAY be updated, replaced, or obsoleted by other documents at any
time.  It is inappropriate to use Internet-Drafts as reference
material or to cite them other than as "work in progress."

This document obsoletes draft-aip-agent-identity-profile-00.

### Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the
document authors.  All rights reserved.

### Changes from draft-aip-agent-identity-profile-00

The following changes were made from the -00 revision:

(a) Added formal definitions for `trust_level` (Section 4.12) and
`lifecycle_state` (Section 4.13) as top-level data model fields.

(b) Added document-level metadata fields (`document_metadata`)
including `issuer`, `issued_at`, `expires_at`, `created_at`, and
`updated_at` (Section 4.14).

(c) Added Privacy Considerations section (Section 13) as required by
IETF process, addressing identifier-based tracking, data
minimization, and cross-domain correlation risks.

(d) Added Conformance Requirements section (Section 15) defining
AIP-Issuer, AIP-Consumer, and AIP-Projector conformance levels.

(e) Strengthened Security Considerations (Section 12) with TLS
requirements, anti-replay mechanisms, rate limiting guidance,
and emergency endpoint authentication requirements.

(f) Corrected normative reference errors: [OIDC-Core] now correctly
references OpenID Connect Core 1.0; RFC 8414 is properly cited
as OAuth 2.0 Authorization Server Metadata; OpenID SSF references
are corrected to the OpenID Shared Signals Framework specification.

(g) Fixed all JSON example syntax errors and ensured consistency
between inline examples and formal field definitions, including
`autonomy_level` string enumeration alignment.

(h) Formalized the extension mechanism (Section 4.15) with namespace
rules, registration requirements, and collision prevention.

(i) Improved protocol integration descriptions for WebFinger
(Section 7.5), A2A Agent Card (Section 11.5), and OpenID SSF
(Section 11.6) with JWS-wrapped event format.

(j) Added JSON Schema definition (Appendix E) for machine-readable
validation.

(k) Added version compatibility and migration guidance
(Section 4.14.1).

---

## Table of Contents

1.  Introduction
    1.1.  Problem Statement
    1.2.  Design Goals
    1.3.  Scope
    1.4.  Relationship to Other Specifications
2.  Terminology and Conventions
3.  Architecture Overview
    3.1.  Protocol Stack Positioning
    3.2.  Architectural Components
    3.3.  Trust Model
4.  AIP Data Model
    4.1.  Top-Level Structure
    4.2.  Agent Identifier (agent_id)
    4.3.  Agent Classification Fields
    4.4.  Framework Descriptor (framework)
    4.5.  Owner Binding (owner_binding)
    4.6.  Capability Declaration (capabilities)
    4.7.  Attestation (attestation)
    4.8.  Integrity Verification (integrity)
    4.9.  Governance (governance)
    4.10. Credential Lifecycle (credential_lifecycle)
    4.11. Observability (observability)
    4.12. Trust Level (trust_level)
    4.13. Lifecycle State (lifecycle_state)
    4.14. Document Metadata (document_metadata)
    4.15. Extensions (extensions)
5.  AIP Document Partitioning
    5.1.  Rationale
    5.2.  AIP-Static Document
    5.3.  AIP-Dynamic Document
    5.4.  Partitioning Metadata
    5.5.  Caching and Consistency
6.  AIP Lifecycle State Machine
    6.1.  States
    6.2.  State Transitions
    6.3.  Transition Triggers
    6.4.  Protocol Behavior per State
7.  AIP Discovery and Resolution Protocol
    7.1.  Overview
    7.2.  Well-Known Configuration Endpoint
    7.3.  AIP Registry API
    7.4.  Resolution Flow
    7.5.  Cross-Domain Resolution via WebFinger
    7.6.  Error Handling and Fallback
8.  Delegation Chains and Multi-Agent Identity
    8.1.  Delegation Chain Structure
    8.2.  Derived AIP and Scope Narrowing
    8.3.  Delegation Depth Control
    8.4.  Chain Validation Rules
9.  Cross-Domain AIP Projection
    9.1.  Projection Levels
    9.2.  Projection Negotiation Protocol
    9.3.  Field Visibility Rules
10. Integrity Verification Model
    10.1. Core Invariants and Controlled Mutables
    10.2. Verification Triggers
    10.3. Semantic Drift Detection
11. Integration with Existing Protocols
    11.1. Integration with WIMSE (WIT/WPT)
    11.2. Integration with OIDC and OIDC-A
    11.3. Integration with draft-liu AOAT Framework
    11.4. Integration with MCP (Model Context Protocol)
    11.5. Integration with A2A (Agent-to-Agent Protocol)
    11.6. Integration with OpenID Shared Signals Framework
12. Security Considerations
    12.1. Transport Security
    12.2. AIP Document Forgery
    12.3. Replay Attack Prevention
    12.4. Delegation Chain Attacks
    12.5. Integrity Bypass
    12.6. Prompt Injection and Intent Deviation
    12.7. Revocation Timeliness
    12.8. Cross-Domain Information Leakage
    12.9. Trust Anchor Compromise
    12.10. Emergency Endpoint Security
    12.11. Rate Limiting
    12.12. Semantic Drift Model Security
13. Privacy Considerations
    13.1. Identifier-Based Tracking
    13.2. Data Minimization
    13.3. Cross-Domain Correlation
    13.4. Audit Log Privacy
    13.5. Owner Identity Protection
14. IANA Considerations
    14.1. AIP Media Type Registration
    14.2. AIP Well-Known URI Registration
    14.3. AIP Field Registry
    14.4. Agent Type Registry
    14.5. AIP Extension Namespace Registry
15. Conformance Requirements
    15.1. AIP-Issuer Conformance
    15.2. AIP-Consumer Conformance
    15.3. AIP-Projector Conformance
    15.4. Version Negotiation
16. References
    16.1. Normative References
    16.2. Informative References
    Appendix A.  Complete AIP Document Example
    Appendix B.  AIP-to-draft-liu Mapping Table
    Appendix C.  AIP-to-OIDC-A Mapping Table
    Appendix D.  Compliance Mapping (NIST)
    Appendix E.  JSON Schema (Informative)

Authors' Addresses

---

## 1.  Introduction

### 1.1.  Problem Statement

The proliferation of AI agent systems — including coding assistants,
autonomous service agents, and multi-agent orchestration platforms —
has created an urgent need for standardized identity metadata that
goes beyond what existing workload credential and authentication
protocols provide.

Current protocol efforts address important but narrow aspects of the
agent identity problem:

-  WIMSE Workload Identity Tokens (WIT) [I-D.ietf-wimse-workload-creds]
   provide cryptographically verifiable workload credentials, but do
   not describe what an agent is, what it can do, or who is
   responsible for it.

-  The dual-identity credential model
   [I-D.ni-wimse-ai-agent-identity] establishes cryptographic
   bindings between an agent and its owner, but does not define a
   metadata format for describing the agent's attributes beyond the
   binding relationship.

-  The AOAT framework [I-D.liu-agent-operation-authorization] defines
   an `agent_identity` claim with seven baseline fields sufficient
   for operation-level authorization decisions, but insufficient for
   full lifecycle management, cross-domain federation, or behavioral
   auditing.

-  OpenID Connect for Agents (OIDC-A) [OIDC-A] introduces rich
   agent-specific claims (agent_type, agent_model, delegation_chain,
   agent_attestation), but embeds them within the OIDC token flow
   rather than providing a standalone, referenceable identity
   document.

-  The AIMS conceptual framework
   [I-D.klrc-aiagent-auth] identifies nine functional components for
   agent identity management, but does not define concrete data
   structures.

None of these specifications, individually or collectively, provide a
unified, structured, and referenceable document that describes an
agent's complete identity metadata — including its type, capabilities,
trust posture, integrity state, governance policies, and credential
lifecycle — in a format that can be discovered, cached, verified, and
projected across trust domain boundaries.

AIP fills this gap.

### 1.2.  Design Goals

The design of AIP is guided by the following principles:

(a) Protocol Complementarity:  AIP MUST NOT duplicate or conflict
with existing protocol mechanisms.  It provides identity metadata
that existing protocols can reference, not an alternative
authentication or authorization flow.

(b) Layered Disclosure:  AIP MUST support selective disclosure of
identity attributes based on the trust relationship between the
requesting and asserting parties.  Not all consumers of an AIP
document need or SHOULD receive all fields.

(c) Verifiable Integrity:  Every AIP document MUST be
cryptographically signed by its issuing authority.  Consumers
MUST be able to verify that the document has not been tampered
with and that the issuer is authoritative for the claimed trust
domain.

(d) Lifecycle Awareness:  AIP MUST model the full identity lifecycle
of an agent, from creation through active operation, suspension,
and revocation, with well-defined protocol behavior at each
stage.

(e) Federation Readiness:  AIP MUST support cross-domain identity
resolution and trust establishment without requiring a
centralized global registry.

(f) Performance Sensitivity:  AIP MUST separate static metadata from
dynamic state to enable aggressive caching of stable attributes
while ensuring timely propagation of state changes.

(g) Extensibility:  AIP MUST allow domain-specific extensions
without breaking interoperability with conforming
implementations.

(h) Privacy by Design:  AIP MUST incorporate privacy protections as
a core design element, not an afterthought.  Identifier stability,
cross-domain correlation, and data minimization MUST be
addressed at the protocol level.

### 1.3.  Scope

This specification defines:

-  The AIP JSON data model and its field semantics.
-  The document partitioning strategy (AIP-Static and AIP-Dynamic).
-  The lifecycle state machine and state transition rules.
-  The trust posture model and trust level semantics.
-  The discovery and resolution protocol for AIP documents.
-  The delegation chain constraints for multi-agent identity.
-  The cross-domain projection mechanism.
-  The integrity verification model.
-  The integration points with WIMSE, OIDC/OIDC-A, AOAT, MCP, A2A,
   and OpenID SSF.
-  The conformance requirements for issuers, consumers, and
   projectors.

This specification does NOT define:

-  Authentication protocols (deferred to WIMSE, OIDC).
-  Authorization decision logic (deferred to AOAT, OPA, FGA engines).
-  Agent-to-agent communication protocols (deferred to A2A).
-  Tool invocation protocols (deferred to MCP).

### 1.4.  Relationship to Other Specifications

AIP is positioned within the following protocol stack:

```
+-------------------------------------------------------+
|  Authorization Layer                                  |
|  draft-liu-agent-operation-authorization              |
|  (AOAT, operation proposals, evidence)                |
+-------------------------------------------------------+
|  Identity Description Layer  <-- AIP occupies this    |
|  (agent metadata, capabilities, trust posture,        |
|   governance, integrity, lifecycle)                   |
+-------------------------------------------------------+
|  Identity Binding Layer                               |
|  draft-ni-wimse-ai-agent-identity                     |
|  (dual-identity credentials, issuance models)         |
+-------------------------------------------------------+
|  Credential & Authentication Layer                    |
|  WIMSE WIT/WPT, OIDC, OIDC-A, AIMS                   |
|  (workload credentials, proof-of-possession,          |
|   user authentication, agent claims)                  |
+-------------------------------------------------------+
|  Trust Foundation Layer                               |
|  WIMSE Architecture, SPIFFE/SPIRE                     |
|  (trust domains, initial trust establishment)         |
+-------------------------------------------------------+
```

## 2.  Terminology and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals, as shown here.

This document uses the following terms:

Agent:
:  A software entity, typically powered by a large language model
(LLM) or similar AI system, that can autonomously or
semi-autonomously perform tasks on behalf of a human user or
organization.  An agent is a specialized form of workload as
defined by WIMSE [I-D.ietf-wimse-arch].

Agent Identity Profile (AIP):
:  A structured JSON document that describes the complete identity
metadata of an agent, including its identifier, type, owner
binding, capabilities, attestation state, integrity assurances,
trust posture, governance policies, credential lifecycle, and
observability configuration.

AIP-Static:
:  The partition of an AIP document containing declarative,
infrequently-changing identity attributes.  AIP-Static is signed
by the Identity Server and served via HTTPS.

AIP-Dynamic:
:  The partition of an AIP document containing operational state
information that changes frequently during an agent's runtime.
AIP-Dynamic is distributed via event streams (e.g., OpenID SSF).

AIP Registry:
:  A service that stores, manages, and serves AIP documents for
agents within a trust domain.  Analogous to a DNS authoritative
server for agent identity resolution.

AIP Projection:
:  A filtered view of an AIP document that contains only the fields
appropriate for the trust level and business requirements of the
requesting party.  Used in cross-domain scenarios to protect
sensitive organizational information.

Delegation Chain:
:  An ordered sequence of delegation steps that records the
provenance of authority from the original human user through one
or more intermediate agents to the currently acting agent.

Derived AIP:
:  An AIP document created for a delegatee agent in a multi-agent
delegation scenario.  A Derived AIP is cryptographically bound to
its parent AIP and MUST have a capability scope that is a strict
subset of the parent's scope.

Identity Server:
:  The authoritative service responsible for creating, signing,
storing, and managing AIP documents within a trust domain.  In
the context of OIDC, this is typically co-located with or
operated by the OpenID Provider (OP) or Authorization Server (AS).

Owner:
:  The human user or organization that has authorized the creation
of an agent and bears ultimate responsibility for its actions.
Corresponds to the "AI Agent Owner" defined in
[I-D.ni-wimse-ai-agent-identity].

Sponsor:
:  The individual within an organization who is designated as the
lifecycle manager and primary point of contact for a specific
agent instance.  A sponsor MAY or MAY NOT be the same entity as
the owner.

Trust Domain:
:  An administrative domain within which a common set of trust
policies and identity management practices apply.  Aligns with
the WIMSE trust domain concept [I-D.ietf-wimse-arch].

Trust Level:
:  A qualitative assessment of the current trustworthiness of an
agent, derived from attestation results, integrity verification,
behavioral monitoring, and credential status.

## 3.  Architecture Overview

### 3.1.  Protocol Stack Positioning

AIP occupies the Identity Description Layer in the agent protocol
stack.  It does not replace any existing authentication, authorization,
or communication protocol.  Instead, it provides a structured metadata
document that these protocols can reference to make richer, more
informed decisions.

The relationship between AIP and adjacent protocol layers is as
follows:

-  Downward Dependency:  AIP relies on the Trust Foundation Layer
   (WIMSE Architecture, SPIFFE) for trust domain definitions and
   initial trust establishment.  The `agent_id` field in AIP uses
   the WIMSE URI format, which inherently encodes the trust domain.

-  Lateral Integration:  AIP integrates with the Credential &
   Authentication Layer by referencing WIT credentials and OIDC-A
   claims.  AIP fields such as `attestation` and
   `credential_lifecycle` describe the state of credentials managed
   by these protocols without duplicating their issuance logic.

-  Upward Service:  AIP serves the Authorization Layer by providing
   the identity context needed for fine-grained authorization
   decisions.  The AOAT framework can reference AIP via the
   `aip_ref` field in the `agent_identity` claim, enabling
   resource servers to retrieve rich agent metadata without
   inflating token size.

### 3.2.  Architectural Components

An AIP-enabled system consists of the following components:

```
+-------------------+        +-------------------+
|   Agent Runtime   |        |   Identity Server  |
|  (Agent Instance) |------->|   (AIP Registry)   |
|                   |  reg   |                    |
+-------------------+        +--------+-----------+
        |                             |
        | operate                     | serve AIP-Static
        v                             | push AIP-Dynamic (SSF)
+-------------------+        +--------+-----------+
| Resource Server   |<-------| AIP Resolution     |
| (MCP Server,      |  fetch |   Endpoint         |
|  API Endpoint)    |        +--------------------+
+-------------------+
        ^
        |  authorize
+-------------------+
| Authorization     |
| Server (AOAT AS)  |
+-------------------+
```

(a) Agent Runtime:  The execution environment hosting the agent
instance.  Responsible for generating integrity checksums,
reporting attestation evidence, and maintaining the AIP-Dynamic
state.

(b) Identity Server / AIP Registry:  The authoritative source of
AIP-Static documents.  Signs and stores AIP documents, handles
lifecycle state transitions, and exposes discovery endpoints.

(c) AIP Resolution Endpoint:  The HTTP endpoint through which AIP
documents are retrieved.  Supports both direct fetch and
WebFinger-based cross-domain resolution.

(d) Resource Server:  Any service that an agent interacts with
(e.g., MCP Server, API endpoint).  Consumes AIP documents to
make trust and access decisions.

(e) Authorization Server:  The AOAT Authorization Server that
references AIP during the operation authorization flow.

### 3.3.  Trust Model

AIP employs a Federated Endorsement Trust Model.  Rather than
relying on a single issuer to vouch for all aspects of an agent's
identity, AIP allows multiple independent endorsers to attest to
different facets of the agent's identity.

The trust model is structured around the following principles:

(a) Domain-Authoritative Issuance:  The AIP document as a whole
MUST be signed by the Identity Server of the trust domain in
which the agent is registered.  This signature establishes the
document's authenticity and the Identity Server's accountability.

(b) Multi-Faceted Endorsement:  Individual sections of the AIP
document MAY carry additional endorsement signatures from
specialized authorities:

    -  The `integrity` section MAY be endorsed by a software supply
       chain verification service.
    -  The `attestation` section MAY be endorsed by a hardware
       attestation service or TEE provider.
    -  The `owner_binding` section MUST include a proof generated
       through one of the three issuance models defined in
       [I-D.ni-wimse-ai-agent-identity].

(c) Verifier-Determined Trust:  The consumer of an AIP document
(resource server, peer agent, authorization server) determines
which endorsements it requires based on its own trust policy.
This specification does not mandate a universal set of REQUIRED
endorsements; instead, it provides the structural framework for
carrying and verifying them.

## 4.  AIP Data Model

This section defines the complete AIP data model.  An AIP document
is a JSON object conforming to the structure defined below.  All
field names are case-sensitive.

### 4.1.  Top-Level Structure

An AIP document MUST contain the following top-level fields:

```json
{
  "profile_version": "1.0",
  "document_metadata": {
    "issuer": "wimse://trust.example.com",
    "issued_at": "2026-03-07T10:00:00Z",
    "expires_at": "2026-03-08T10:00:00Z",
    "created_at": "2026-03-01T08:00:00Z",
    "updated_at": "2026-03-07T10:00:00Z",
    "document_id": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "nonce": "n-0S6_WzA2Mj"
  },
  "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
  "agent_type": "coding",
  "display_name": "Enterprise Coding Assistant",
  "agent_model": "gpt-4",
  "agent_provider": "openai.com",
  "agent_instance_id": "instance-abc-123",
  "framework": {
    "name": "enterprise-coding-assistant",
    "version": "1.0"
  },
  "owner_binding": {
    "binding_model": "server_mediated",
    "owner_id": "urn:entity:org:example-corp"
  },
  "capabilities": {
    "declared": [
      {"capability": "file.read"},
      {"capability": "code.generate"}
    ],
    "autonomy_level": "human_on_the_loop"
  },
  "attestation": {
    "format": "urn:ietf:params:oauth:token-type:eat",
    "timestamp": "2026-03-07T10:00:00Z",
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVhdCtqd3QifQ..."
  },
  "integrity": {
    "core_invariants": {
      "system_config_hash": "SHA-256:b2c3d4e5f6a7..."
    },
    "composite_hash": "SHA-256:d4e5f6a7b8c9..."
  },
  "governance": {
    "sponsor": {
      "id": "admin@example.com",
      "responsibility": "lifecycle_owner"
    },
    "risk_classification": "medium"
  },
  "credential_lifecycle": {
    "primary_credential": {
      "type": "WIT",
      "rotation_interval": "PT1H"
    }
  },
  "observability": {
    "audit_log_endpoint": "https://audit.example.com/agent-events",
    "event_types": ["credential_issued", "authorization_granted"]
  },
  "trust_level": "verified",
  "lifecycle_state": "active",
  "document_partitioning": {
    "partition_strategy": "static_dynamic_split",
    "sync_interval": 300
  }
}
```

The following top-level fields are OPTIONAL:

-  `agent_version`:  The version identifier of the agent model.
-  `extensions`:  A JSON object for domain-specific extensions
   (see Section 4.15).

### 4.2.  Agent Identifier (agent_id)

The `agent_id` field uniquely identifies an agent within and across
trust domains.

-  Format:  MUST be a valid WIMSE URI as defined in
   [I-D.ietf-wimse-arch], or a valid SPIFFE ID as defined in
   [SPIFFE].

-  Structure:  `wimse://<trust-domain>/<path>`, where `<trust-domain>`
   identifies the administrative domain and `<path>` identifies the
   specific agent within that domain.

-  Stability:  The `agent_id` MUST remain stable for the entire
   lifecycle of the agent identity, including across credential
   rotations, configuration updates, and runtime restarts.  This
   aligns with [I-D.klrc-aiagent-auth] Section 5, which requires
   that identifiers remain stable for the lifetime of the workload
   identity.

-  Interoperability:  For systems that require a `urn:uuid:` format
   (e.g., the `id` field in [I-D.liu-agent-operation-authorization]
   `agent_identity` claim), the Identity Server MUST maintain a
   deterministic mapping between the WIMSE URI and the
   corresponding UUID.

-  Privacy:  The `agent_id` is a stable identifier that MAY be used
   for cross-domain correlation.  Implementations SHOULD consider
   the privacy implications described in Section 13.1 and MAY use
   pairwise identifiers for cross-domain scenarios where appropriate.

Example:

```
wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000
```

### 4.3.  Agent Classification Fields

The following fields classify the agent and are anchored to
OIDC-A [OIDC-A] Section 2.1 and Section 2.4.1:

agent_type (REQUIRED):
:  Classifies the agent's operational role.  MUST be one of the
following registered values: "assistant", "retrieval", "coding",
"domain_specific", "autonomous", "supervised".  Custom types
MUST use the format `<vendor>:<type>` (e.g.,
"acme:financial_advisor").  The Authorization Server MAY apply
different default policy templates based on the `agent_type`
value.

agent_model (REQUIRED):
:  Identifies the LLM or AI model powering the agent (e.g.,
"gpt-4", "claude-3-opus", "gemini-pro").  Resource servers MAY
use this field to apply model-specific trust policies.

agent_version (OPTIONAL):
:  The version identifier of the agent model (e.g., "2026-03").

agent_provider (REQUIRED):
:  The organization that created, trained, or hosts the agent.
SHOULD use domain name format (e.g., "openai.com",
"anthropic.com").

agent_instance_id (REQUIRED):
:  A unique identifier for this specific agent instance,
distinguishing it from other instances of the same model and
configuration.

display_name (REQUIRED):
:  A human-readable name for the agent, intended for display in
user interfaces and audit logs.  MUST NOT exceed 256 UTF-8
characters.  SHOULD be meaningful in the context of the
organization or deployment environment.

### 4.4.  Framework Descriptor (framework)

The `framework` object describes the agent's runtime environment
and protocol capabilities.

```json
{
  "framework": {
    "name": "OpenClaw",
    "version": "2026.2.25",
    "runtime": "node:20-alpine",
    "protocol_support": ["MCP/1.0", "A2A/0.2"],
    "attestation_formats_supported": ["EAT", "TPM2-Quote"],
    "delegation_methods_supported": ["oauth2", "jwt"]
  }
}
```

Field definitions:

name (REQUIRED):
:  The name of the agent framework.

version (REQUIRED):
:  The version of the agent framework.

runtime (OPTIONAL):
:  The runtime environment identifier (e.g., container image,
OS version).

protocol_support (OPTIONAL):
:  An array of protocol identifiers that the agent supports.
Each entry SHOULD follow the format `<protocol>/<version>`.

attestation_formats_supported (OPTIONAL):
:  Attestation evidence formats the agent can produce.  Aligns
with OIDC-A Section 4.1 `attestation_formats_supported`.

delegation_methods_supported (OPTIONAL):
:  Delegation mechanisms the agent supports.  Aligns with OIDC-A
Section 4.1 `delegation_methods_supported`.

### 4.5.  Owner Binding (owner_binding)

The `owner_binding` object establishes the cryptographic and
governance relationship between the agent and its owner.  This is
one of the most security-critical sections of the AIP document.

```json
{
  "owner_binding": {
    "owner_type": "user | organization",
    "owner_id": "user@example.com",
    "binding_model": "agent_mediated | owner_mediated | server_mediated",
    "binding_proof": {
      "proof_type": "dual_identity_credential",
      "owner_public_key_thumbprint": "SHA-256:a1b2c3d4...",
      "binding_timestamp": "2026-03-07T10:00:00Z",
      "attestation_method": "hardware_key | software_signature | biometric"
    },
    "delegation_authority": {
      "can_delegate": false,
      "max_delegation_depth": 0,
      "delegation_scope_ceiling": [],
      "delegation_purpose": "",
      "delegation_constraints": {}
    },
    "delegation_chain": []
  }
}
```

#### 4.5.1.  Binding Models

The `binding_model` field indicates which of the three issuance
models defined in [I-D.ni-wimse-ai-agent-identity] was used to
establish the owner-agent binding:

agent_mediated:
:  The agent generates a key pair locally.  The owner provides a
co-signature using a local signing device (e.g., FIDO2 security
key, platform authenticator).  This model does not require
network communication with the Identity Server at binding time.
Suitable for individual developers and local-first deployments.

owner_mediated:
:  An Identity Proxy operated by the owner's organization
intercepts the agent's identity request and applies
organizational policy before completing the binding.  Suitable
for enterprise deployments where centralized governance is
REQUIRED.

server_mediated:
:  The Identity Server mediates the binding by sending an
out-of-band challenge to the owner (push notification, email,
SMS) and completing the binding only upon owner confirmation.
Provides the strongest security guarantees.  Suitable for
high-assurance scenarios and remote agent deployments.

#### 4.5.2.  Binding Proof

The `binding_proof` object contains evidence of the owner-agent
binding.  Its contents vary depending on the `binding_model`:

-  For `agent_mediated`:  `owner_public_key_thumbprint` contains the
   thumbprint of the owner's public key used for co-signing.
   `attestation_method` indicates the type of owner credential used.

-  For `owner_mediated`:  `binding_proof` MAY additionally contain
   an organizational policy reference indicating which policies were
   evaluated during binding.

-  For `server_mediated`:  `binding_proof` MUST contain a reference
   to the Identity Server's binding confirmation record.

#### 4.5.3.  Delegation Authority

The `delegation_authority` object defines whether and how this agent
MAY delegate tasks to other agents.

can_delegate (REQUIRED):
:  Boolean.  If false, this agent MUST NOT create Derived AIPs
or delegate any of its authority to other agents.  Defaults to
false.

max_delegation_depth (REQUIRED when can_delegate is true):
:  A non-negative integer specifying the maximum number of
delegation hops permitted from this agent.  A value of 0
(when can_delegate is true) means this agent can delegate to
direct children only, who themselves cannot further delegate.

delegation_scope_ceiling (REQUIRED when can_delegate is true):
:  An array of capability identifiers that MAY be delegated.
MUST be a subset of the agent's own declared capabilities.

delegation_purpose (OPTIONAL):
:  A human-readable description of the intended purpose of
delegation.

delegation_constraints (OPTIONAL):
:  Additional constraints on delegation, such as `max_duration`
(in seconds) and `allowed_resources` (array of resource
path patterns).

#### 4.5.4.  Delegation Chain

The `delegation_chain` array records the provenance of delegated
authority.  This structure aligns with OIDC-A Section 2.4.2.

Each element in the array represents one delegation step and MUST
contain:

```json
{
  "iss": "...",
  "sub": "...",
  "aud": "...",
  "delegated_at": "2026-03-07T10:00:00Z",
  "scope": "...",
  "purpose": "...",
  "constraints": {
    "max_duration": 3600,
    "allowed_resources": ["..."]
  },
  "jti": "..."
}
```

Validation rules for delegation chains are defined in Section 8.4.

### 4.6.  Capability Declaration (capabilities)

The `capabilities` object declares what the agent can do and what it
is restricted from doing.

```json
{
  "capabilities": {
    "declared": [
      {
        "capability": "file.read",
        "scope": "/workspace/**",
        "risk_level": "low",
        "mcp_tool_ref": "filesystem/readFile"
      }
    ],
    "restricted": [
      {
        "capability": "credentials.access",
        "restriction_reason": "owner_policy | platform_default | regulatory",
        "override_requires": "step_up_auth | sponsor_approval | never"
      }
    ],
    "autonomy_level": "human_in_the_loop | human_on_the_loop | human_out_of_the_loop"
  }
}
```

#### 4.6.1.  Declared Capabilities

Each entry in the `declared` array describes a capability the agent
is authorized to exercise:

capability (REQUIRED):
:  A capability identifier using dot-notation (e.g., "file.read",
"code.execute", "web.browse").  Custom capabilities MUST use
the format `<vendor>:<capability>` (e.g., "acme:trade").

scope (RECOMMENDED):
:  A resource scope pattern defining the subset of resources to
which this capability applies.  The syntax of scope patterns is
implementation-specific, but implementations MUST support at
least the glob pattern semantics defined by [RFC 3986]
Section 3.3.

risk_level (REQUIRED):
:  One of "low", "medium", "high", "critical".  Resource servers
MUST use this field to apply appropriate authorization scrutiny.

mcp_tool_ref (OPTIONAL):
:  A reference to the corresponding MCP tool definition, if this
capability maps to an MCP tool call.

#### 4.6.2.  Restricted Capabilities

Each entry in the `restricted` array describes a capability that is
available but subject to additional controls:

restriction_reason (REQUIRED):
:  The reason for the restriction.  MUST be one of:
"owner_policy" (restricted by the owner's explicit policy),
"platform_default" (restricted by platform default rules),
"regulatory" (restricted by legal or regulatory requirements).

override_requires (REQUIRED):
:  The conditions under which the restriction can be overridden.
MUST be one of: "step_up_auth" (requires multi-factor
authentication), "sponsor_approval" (requires explicit approval
by the sponsor), "never" (the capability is permanently denied).

#### 4.6.3.  Autonomy Level

The `autonomy_level` field indicates the agent's decision-making
autonomy:

human_in_the_loop:
:  The agent requires explicit human approval for every action.

human_on_the_loop:
:  The agent can act autonomously for low-risk operations but
requires human approval for higher-risk operations.  Risk
thresholds are determined by the Authorization Server based on
trust level and policy.

human_out_of_the_loop:
:  The agent can act autonomously within its declared capabilities
without requiring real-time human approval.  Post-hoc audit
and anomaly detection MUST be enabled for this mode.

### 4.7.  Attestation (attestation)

The `attestation` object contains evidence proving that the agent's
runtime environment and software stack are in a trusted state.

```json
{
  "attestation": {
    "format": "urn:ietf:params:oauth:token-type:eat",
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVhdCtqd3QifQ...",
    "timestamp": "2026-03-07T10:00:00Z",
    "verification_endpoint": "https://auth.example.com/agent/attestation",
    "evidence_type": "eat_profile | raw_tcb | custom",
    "evidence_ref": "urn:ietf:params:eat:ai-agent:v1",
    "attestation_results": {
      "platform": {
        "type": "container | vm | bare_metal | tee",
        "orchestrator": "kubernetes | docker | custom",
        "namespace": "<namespace>",
        "verified": true
      },
      "software": {
        "binary_hash": "SHA-256:e5f6a7b8...",
        "config_hash": "SHA-256:c3d4e5f6...",
        "supply_chain_verified": true
      },
      "hardware": {
        "tpm_present": false,
        "secure_enclave": false,
        "key_protection": "software | tee | hsm"
      }
    },
    "last_attestation_time": "2026-03-07T10:00:00Z",
    "next_attestation_deadline": "2026-03-07T11:00:00Z"
  }
}
```

Field definitions:

format (REQUIRED):
:  The format of the attestation token.  RECOMMENDED value is
"urn:ietf:params:oauth:token-type:eat" (Entity Attestation
Token as defined by [I-D.ietf-rats-eat]).

token (REQUIRED):
:  The base64url-encoded attestation token.

timestamp (REQUIRED):
:  The RFC 3339 timestamp when the attestation was generated.

verification_endpoint (REQUIRED):
:  The HTTPS endpoint where the attestation token can be verified.
Aligns with OIDC-A Section 5.1 agent_attestation endpoint.

evidence_type (REQUIRED):
:  The type of attestation evidence.  "eat_profile" indicates a
profile-based EAT; "raw_tcb" indicates raw TCB measurements;
"custom" indicates a custom format.

evidence_ref (RECOMMENDED):
:  A reference identifier linking to known-good measurements or
baseline values for the attestation evidence.

attestation_results (REQUIRED):
:  The parsed and verified results of the attestation.  Contains
three sub-objects:

-  platform:  Describes the execution environment.
   `type` MUST be one of: "container", "vm", "bare_metal",
   "tee".  `verified` indicates whether the platform attestation
   succeeded.

-  software:  Describes the software stack.  `binary_hash` is
   the hash of the agent binary; `config_hash` is the hash of
   the agent configuration; `supply_chain_verified` indicates
   whether the software supply chain was verified.

-  hardware:  Describes hardware security features.  All
   fields are OPTIONAL.  If hardware attestation is present,
   Identity Servers SHOULD increase the trust level for this
   agent.

last_attestation_time (REQUIRED):
:  The RFC 3339 timestamp of the last successful attestation.

next_attestation_deadline (REQUIRED):
:  The RFC 3339 timestamp by which a new attestation MUST be
provided.  Failure to attest before this deadline SHALL result in
the agent being suspended or revoked.

### 4.8.  Integrity Verification (integrity)

The `integrity` object provides cryptographic evidence that the
agent's configuration has not been tampered with.  This is a
defense-in-depth measure against prompt injection attacks and
configuration tampering.

```json
{
  "integrity": {
    "core_invariants": {
      "system_config_hash": "SHA-256:b2c3d4e5f6a7...",
      "security_policy_hash": "SHA-256:e5f6a7b8c9d0..."
    },
    "controlled_mutables": {
      "tools_config": {
        "mutation_policy": "append_only | version_tracked | strict",
        "allowed_sources": ["registry.mcp.example.com"],
        "change_audit_required": true
      },
      "prompt_template": {
        "mutation_policy": "version_tracked",
        "max_drift_from_baseline": 0.3,
        "change_audit_required": true
      }
    },
    "composite_hash": "SHA-256:d4e5f6a7b8c9...",
    "verification_endpoint": "https://auth.example.com/agents/verify-integrity",
    "last_verified": "2026-03-07T10:00:00Z"
  }
}
```

The integrity model is described in detail in Section 10.

### 4.9.  Governance (governance)

The `governance` object defines organizational policies and
lifecycle management parameters for the agent.

```json
{
  "governance": {
    "sponsor": {
      "type": "user | role",
      "id": "admin@example.com",
      "responsibility": "lifecycle_owner | operator | auditor",
      "contact_channel": {
        "type": "email | phone | internal_messaging",
        "address": "admin@example.com"
      }
    },
    "lifecycle_policy": {
      "max_idle_duration": "PT72H",
      "auto_deactivation": true,
      "credential_rotation_interval": "PT1H",
      "mandatory_review_interval": "P7D",
      "decommission_procedure": "<procedure reference URL>"
    },
    "compliance_requirements": ["SOC2", "GDPR", "HIPAA"],
    "risk_classification": "low | medium | high | critical"
  }
}
```

Field definitions:

sponsor (REQUIRED):
:  The individual or role responsible for the agent's lifecycle
management.  The `responsibility` field indicates the type of
responsibility: "lifecycle_owner" (primary owner), "operator"
(day-to-day operator), "auditor" (responsible for compliance
audits).

lifecycle_policy (REQUIRED):
:  Parameters governing the agent's lifecycle.  All duration fields
use ISO 8601 duration format [ISO.8601.2004]:

-  max_idle_duration:  Maximum idle time before the agent is
   automatically suspended.

-  auto_deactivation:  If true, the agent is automatically
   suspended after max_idle_duration.

-  credential_rotation_interval:  Recommended interval for
   credential rotation.

-  mandatory_review_interval:  Interval at which the agent
   configuration MUST be reviewed by the sponsor.

-  decommission_procedure:  Reference to the decommissioning
   procedure document.

compliance_requirements (OPTIONAL):
:  Array of regulatory or compliance frameworks to which this
agent is subject.  Values MUST be drawn from a registry managed
by the organization's governance team.

risk_classification (REQUIRED):
:  The risk classification of this agent as assessed by the
organization's risk management function.  MUST be one of:
"low", "medium", "high", "critical".  This value SHOULD be
consistent with or higher than the highest `risk_level` declared
in `capabilities`.

### 4.10.  Credential Lifecycle (credential_lifecycle)

The `credential_lifecycle` object tracks the status of the agent's
credentials across the WIMSE and OIDC ecosystems.

```json
{
  "credential_lifecycle": {
    "primary_credential": {
      "type": "WIT | X.509-SVID | JWT-SVID",
      "issuer": "<trust domain URI>",
      "current_credential_id": "<credential identifier>",
      "issued_at": "2026-03-07T10:00:00Z",
      "expires_at": "2026-03-07T11:00:00Z",
      "rotation_status": "active | rotating | failed"
    },
    "binding_credential": {
      "type": "dual_identity_credential",
      "binding_model": "agent_mediated | owner_mediated | server_mediated",
      "issued_at": "2026-03-07T09:55:00Z",
      "expires_at": "2026-03-08T09:55:00Z"
    },
    "secondary_credentials": [
      {
        "type": "oauth2_token",
        "target_system": "github.com",
        "exchange_mechanism": "token_exchange | grant_exchange",
        "scope": "repo:read",
        "expires_at": "2026-03-07T10:30:00Z"
      }
    ],
    "revocation": {
      "revocation_endpoint": "https://auth.example.com/agents/revoke",
      "revocation_check_interval": "PT5M",
      "emergency_kill_switch": "https://auth.example.com/agents/emergency-stop",
      "ssf_stream_id": "stream-agent-events-001"
    }
  }
}
```

Field definitions:

primary_credential (REQUIRED):
:  The main credential used for workload identity as defined by
WIMSE [I-D.ietf-wimse-workload-creds].  The `type` field MUST
be one of: "WIT" (Workload Identity Token), "X.509-SVID"
(X.509 SPIFFE Verifiable Identity Document), "JWT-SVID" (JWT
SPIFFE Verifiable Identity Document).  The `rotation_status`
field indicates the current rotation state: "active" (credential
is valid), "rotating" (credential rotation is in progress),
"failed" (credential rotation failed, manual intervention
REQUIRED).

binding_credential (OPTIONAL but RECOMMENDED):
:  The dual-identity credential binding the agent to its owner
as defined in [I-D.ni-wimse-ai-agent-identity].  The lifecycle
of the binding credential is typically longer than that of the
primary credential.

secondary_credentials (OPTIONAL):
:  Array of credentials obtained through token exchange with
external systems as defined in [RFC 8693] (OAuth 2.0 Token
Exchange).  Each entry specifies the credential type, target
system, exchange mechanism, scope, and expiration time.

revocation (REQUIRED):
:  Parameters for revocation checking and emergency revocation:

-  revocation_endpoint:  HTTPS endpoint for manual revocation.
-  revocation_check_interval:  Interval at which the agent
   MUST check revocation status.  RECOMMENDED default is PT5M.
-  emergency_kill_switch:  Emergency revocation endpoint that
   bypasses normal revocation checking and immediately revokes
   all credentials.  RECOMMENDED for agents with
   autonomy_level "human_out_of_the_loop".  See Section 12.10
   for security requirements.
-  ssf_stream_id:  OpenID Shared Signals Framework stream ID
   for receiving revocation events.

### 4.11.  Observability (observability)

The `observability` object defines how an agent's events are
monitored, logged, and audited.

```json
{
  "observability": {
    "audit_log_endpoint": "https://audit.example.com/agent-events",
    "event_types": [
      "credential_issued",
      "authorization_granted",
      "authorization_denied",
      "policy_violation",
      "delegation_created",
      "integrity_failure"
    ],
    "ssf_config": {
      "caep_stream_id": "stream-agent-caep-events-001",
      "risc_stream_id": "stream-agent-risc-events-001"
    },
    "correlation_id_scheme": "urn:uuid",
    "behavior_monitoring": {
      "enabled": true,
      "baseline_model_ref": "<reference>",
      "anomaly_threshold": 0.85,
      "alert_endpoints": ["<alerting service URIs>"]
    },
    "discovery_endpoints": {
      "agent_attestation_endpoint": "https://auth.example.com/agent/attestation",
      "agent_capabilities_endpoint": "https://auth.example.com/.well-known/agent-capabilities"
    }
  }
}
```

Field definitions:

audit_log_endpoint (REQUIRED):
:  HTTPS endpoint where audit events are submitted.

event_types (REQUIRED):
:  Array of event types that the agent generates.  Implementations
MUST support at least the event types listed in the example.

ssf_config (RECOMMENDED):
:  Configuration for OpenID Shared Signals Framework
[OIDC-SSF] event subscriptions.  `caep_stream_id` is for
Continuous Access Evaluation Profile events; `risc_stream_id`
is for RISC events.

correlation_id_scheme (REQUIRED):
:  The scheme used for generating correlation IDs across events.
RECOMMENDED value is "urn:uuid".

behavior_monitoring (OPTIONAL):
:  Configuration for real-time behavioral anomaly detection.  If
enabled, the agent's behavior is continuously compared against
a baseline model, and alerts are generated when the anomaly
score exceeds the threshold.

discovery_endpoints (OPTIONAL):
:  Endpoints for discovering agent-specific services.  Aligns
with OIDC-A Section 4.2.

### 4.12.  Trust Level (trust_level)

The `trust_level` field provides a qualitative assessment of the
agent's current trustworthiness.  This is a REQUIRED top-level field
that enables resource servers and authorization servers to make
context-aware authorization decisions.

The trust level is computed by the Identity Server based on multiple
factors:

-  Attestation results (hardware TEE vs. software-only)
-  Integrity verification status
-  Behavioral anomaly detection
-  Credential status and rotation history
-  Policy compliance history

The following trust levels are defined:

unverified:
:  The agent's identity has not been verified.  This is the initial
state for newly created agents before successful attestation.
Resource Servers SHOULD treat agents with this level with
maximum scrutiny and MAY deny access to sensitive resources.

verified:
:  The agent has successfully completed standard attestation and
integrity verification.  Hardware attestation is not required.
This is the expected level for most operational agents in
low-to-medium-risk environments.

trusted:
:  The agent has additional trust assurances beyond basic
verification.  This typically requires:
-  Hardware attestation (TPM, TEE, secure enclave)
-  Supply chain verification
- Consistent behavioral profile with no anomalies
-  Successful completion of any required security training or
certification

highly_trusted:
:  The agent has the highest level of trust assurance.  This
typically requires:
-  All requirements for "trusted"
-  Extended observation period (e.g., 30 days) with no
policy violations
-  Active monitoring with real-time anomaly detection
-  Explicit designation by the organization's security team
-  May be required for agents with autonomy_level
"human_out_of_the_loop"

compromised:
:  The agent has been detected as compromised or has exhibited
behavior consistent with a security incident.  This is a
critical state that requires immediate action.  Agents with
this trust level MUST be suspended or revoked.  See Section
6.2 for state transition details.

Trust Level Transitions:

-  Transitions MUST follow the directionality rules:
   unverified -> verified -> trusted -> highly_trusted
-  Downgrade transitions (e.g., trusted -> verified) are
   permitted based on changing conditions (e.g., attestation
   expiration, hardware key loss)
-  Transition to "compromised" is permitted from any level
-  Recovery from "compromised" requires explicit remediation and
   re-verification, with the agent typically starting at "unverified"

Trust Level Use in Authorization:

-  Resource Servers SHOULD use `trust_level` as an additional
   authorization factor
-  High-risk capabilities (risk_level: "critical") MAY require
   `trust_level: "highly_trusted"`
-  Authorization Servers MAY adjust the `autonomy_level` based on
   `trust_level` (e.g., downgrade "human_out_of_the_loop" to
   "human_on_the_loop" for agents with `trust_level: "verified"`)

### 4.13.  Lifecycle State (lifecycle_state)

The `lifecycle_state` field indicates the current state of the
agent's identity lifecycle.  This is a REQUIRED top-level field.

The following states are defined:

created:
:  The AIP document has been generated but has not yet received
all required endorsements and attestations.  In this state,
the agent MUST NOT be used for any operational tasks.  This is
a transient initialization state.

active:
:  The AIP document has been fully endorsed, attested, and the agent
is authorized to operate within its declared capabilities.
This is the normal operating state for agents.

suspended:
:  The agent has been temporarily suspended due to a detected
anomaly, policy violation, integrity failure, or explicit
administrative action.  In this state:
-  Ongoing operations MAY be allowed to complete gracefully
-  New operations MUST be rejected
-  The agent MAY return to the active state after the suspension
cause is resolved

revoked:
:  The AIP document has been permanently revoked.  This is an
irreversible terminal state.  All credentials MUST be
invalidated immediately.  All ongoing operations SHOULD be
terminated where possible.  Common causes include:
-  Owner or sponsor explicit revocation
-  Security incident or compromise detection
-  Failure to remediate a suspension within a grace period
-  Regulatory or legal requirement

decommissioned:
:  The agent has been formally decommissioned according to the
decommissioning procedure documented in
`governance.lifecycle_policy.decommission_procedure`.  This is
an irreversible terminal state reached after a planned shutdown
process.  Decommissioned agents have:
-  All credentials invalidated
-  All resources released
-  Final audit logs generated
-  Lifecycle records archived

State Machine Details:

The complete state machine with transition triggers is defined in
Section 6.  Implementations MUST follow the state transition
rules defined there.

### 4.14.  Document Metadata (document_metadata)

The `document_metadata` object contains metadata about the AIP
document itself, separate from the agent's identity attributes.
This is a REQUIRED field that supports document lifecycle management
and security.

```json
{
  "document_metadata": {
    "issuer": "wimse://trust.example.com",
    "issued_at": "2026-03-07T10:00:00Z",
    "expires_at": "2026-03-08T10:00:00Z",
    "created_at": "2026-03-01T08:00:00Z",
    "updated_at": "2026-03-07T10:00:00Z",
    "document_id": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "nonce": "n-0S6_WzA2Mj"
  }
}
```

Field definitions:

issuer (REQUIRED):
:  The identity of the entity that issued this AIP document.
Typically the trust domain URI of the Identity Server.
Consumers MUST verify that the JWS signature matches this
issuer.

issued_at (REQUIRED):
:  The RFC 3339 timestamp when this specific version of the AIP
document was issued.  This value is set each time the document
is signed and issued.

expires_at (REQUIRED):
:  The RFC 3339 timestamp after which this version of the AIP
document SHOULD be considered invalid.  Consumers SHOULD fetch
a fresh version after this time.  The expiration interval
SHOULD be aligned with the credential rotation interval and
attestation deadlines.

created_at (REQUIRED):
:  The RFC 3339 timestamp when the agent's identity (and the first
AIP document) was created.  This value MUST remain stable
across all versions of the AIP document and is used for
lifecycle auditing.

updated_at (REQUIRED):
:  The RFC 3339 timestamp when this version of the AIP document
was last modified.  This value changes each time the document
is updated.

document_id (REQUIRED):
:  A unique identifier for this specific version of the AIP
document.  MUST be a URN UUID [RFC 4122].  This identifier is
used for:
-  Document-level audit logging
-  Cache invalidation
-  Version tracking in document history

nonce (REQUIRED):
:  A cryptographic nonce used to prevent replay attacks of the
AIP document itself.  The nonce MUST be:
-  Unique across all AIP documents issued by the same issuer
-  At least 128 bits of entropy
-  Included in the JWS payload and protected by the signature
Consumers MUST verify that nonces are not reused within the
issuer's validity window.  See Section 12.3 for additional
replay attack prevention details.

#### 4.14.1.  Version Compatibility

The `profile_version` field indicates the version of the AIP
specification that this document conforms to.  The format is
MAJOR.MINOR where:

-  MAJOR:  Incremented for incompatible changes that require
   consumers to update their implementation
-  MINOR:  Incremented for backward-compatible additions

Version Compatibility Rules:

-  Consumers MUST reject documents with a higher MAJOR version
   number than they support
-  Consumers MAY process documents with a higher MINOR version
   number by ignoring unknown fields
-  Consumers MUST process documents with a lower MINOR version
   number according to backward compatibility rules
-  The current version is "1.0"

Migration Guidance:

When `profile_version` changes, Identity Servers SHOULD:
-  Maintain a grace period during which both old and new versions
   are supported
-  Provide migration tools for upgrading AIP documents
-  Document breaking changes in release notes

### 4.15.  Extensions (extensions)

The `extensions` object allows domain-specific extensions to the AIP
document without breaking interoperability.  This is an OPTIONAL
field.

```json
{
  "extensions": {
    "acme": {
      "department": "engineering",
      "cost_center": "ENG-001",
      "approval_chain": ["manager@example.com", "director@example.com"]
    },
    "compliance": {
      "data_classification": "confidential",
      "jurisdiction": "GDPR"
    }
  }
}
```

Extension Namespace Rules:

To prevent naming conflicts, extension fields MUST follow these
rules:

1.  Top-Level Keys:  Each top-level key in the `extensions` object
    MUST be a registered namespace identifier.  Namespace
    identifiers are managed via the IANA AIP Extension Namespace
    Registry (Section 14.5).

2.  Registration:  Before using a namespace identifier, implementers
    MUST register it with the IANA registry.  The registration
    MUST include:
    -  Namespace identifier
    -  Contact information for the maintainer
    -  Reference to the extension specification
    -  Version of the extension

3.  Collision Prevention:  The following patterns are RESERVED
    and MUST NOT be used as namespace identifiers:
    -  Any field name that conflicts with standard AIP top-level
       fields
    -  Names starting with "x-" (these are reserved for experimental
       use and MUST NOT be used in production)
    -  Single-character names

4.  Extension Semantics:  Within each namespace, the implementer
    defines the structure and semantics of the extension data.
    However:
    -  Extension data MUST be valid JSON
    -  Extensions MUST NOT modify the semantics of standard AIP
       fields
    -  Extensions MUST NOT introduce authentication or authorization
       bypass mechanisms

5.  Extension Ignoration:  Consumers MAY ignore any extension
    namespaces they do not recognize.  However:
    -  Consumers MUST NOT reject the entire AIP document due to
       unknown extensions
    -  Consumers SHOULD log receipt of unknown extensions for
       audit purposes

6.  Security Considerations:  Extensions MAY introduce security
    risks.  Implementers and consumers MUST:
    -  Perform security review of extension specifications
    -  Consider whether extensions introduce new attack surfaces
    -  Apply the same verification and validation to extension
       data as to standard AIP fields

Example of Reserved Namespaces:

The following namespace identifiers are reserved for future
standardization:
-  "privacy":  For privacy-related extensions
-  "security":  For security-related extensions
-  "performance":  For performance monitoring extensions
-  "compliance":  For compliance-related extensions

Experimental extensions SHOULD use the "x-" prefix and MUST NOT be
used in production deployments.

## 5.  AIP Document Partitioning

### 5.1.  Rationale

AIP documents contain two types of information with fundamentally
different update frequencies and access patterns:

(a) Declarative Metadata:  Identity attributes that describe what
the agent is: `agent_id`, `agent_type`, `framework`,
`owner_binding`, `capabilities`, `governance`, `integrity.core_invariants`.
These change rarely (only on configuration updates) and can be
aggressively cached.

(b) Dynamic State:  Operational state information that changes
frequently: `credential_lifecycle` current status, current
attestation results, trust level, behavioral anomalies.  These
change frequently (potentially every second) and require timely
propagation.

Storing both types of information in a single document would force
a trade-off: either cache aggressively (risking stale dynamic state)
or fetch frequently (wasting bandwidth on unchanged declarative
metadata).

AIP solves this by partitioning documents into AIP-Static and
AIP-Dynamic, each with its own storage, serving, and caching strategy.

### 5.2.  AIP-Static Document

AIP-Static contains all declarative metadata fields.  It is signed
by the Identity Server and served via HTTPS with long cache TTLs.

AIP-Static MUST include the following fields:

-  All fields defined in Sections 4.2 through 4.9
-  `trust_level` initial assessment (Section 4.12); note that
   the real-time computed trust level is maintained in AIP-Dynamic
-  `lifecycle_state` (Section 4.13)
-  `document_metadata` (Section 4.14)
-  `extensions` if present (Section 4.15)
-  `document_partitioning.static_ref` (self-reference)
-  `document_partitioning.static_etag` (version identifier)
-  `document_partitioning.dynamic_ssf_stream` (event stream endpoint)

AIP-Static MUST NOT include:

-  `credential_lifecycle.primary_credential.rotation_status`
-  `attestation.last_attestation_time` (static attestation
   configuration is included, but the timestamp is not)
-  Any real-time behavioral monitoring data
-  Real-time `trust_level` updates (these are propagated via
   AIP-Dynamic events; the AIP-Static document carries only the
   trust level as of document issuance time)

AIP-Static documents MUST be signed using JWS [RFC 7515].  The
`alg` header parameter MUST indicate a secure signature algorithm
(e.g., RS256, ES256).  The `kid` header parameter MUST identify
the signing key, which MUST be discoverable via the Identity
Server's JWKS endpoint [RFC 7517].

### 5.3.  AIP-Dynamic Document

AIP-Dynamic contains frequently-changing operational state.  It is
distributed via event streams (e.g., OpenID SSF) rather than as a
single document.

AIP-Dynamic events are signed individually and pushed to subscribers
in real-time.  Each event MUST be JWS-wrapped with the following
structure:

```json
{
  "payload": {
    "event_type": "credential_rotated",
    "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-03-07T10:00:00Z",
    "event_id": "evt-12345",
    "data": { ... }
  },
  "signature": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

The `data` object contains the specific state change.  For example,
a `credential_rotated` event might contain:

```json
{
  "event_type": "credential_rotated",
  "agent_id": "wimse://trust.example.com/agents/...",
  "timestamp": "2026-03-07T10:00:00Z",
  "event_id": "evt-12345",
  "data": {
    "credential_id": "urn:uuid:credential-abc-123",
    "previous_expires_at": "2026-03-07T10:00:00Z",
    "new_expires_at": "2026-03-07T11:00:00Z",
    "rotation_status": "active"
  }
}
```

Supported AIP-Dynamic event types:

-  `trust_level_changed`:  When the agent's trust level changes
-  `credential_rotated`:  When a credential is rotated
-  `attestation_updated`:  When attestation results are updated
-  `lifecycle_state_changed`:  When the lifecycle state changes
-  `integrity_failure`:  When integrity verification fails
-  `behavioral_anomaly`:  When behavioral anomalies are detected
-  `policy_violation`:  When a policy violation is detected

If event streaming is not available, AIP-Dynamic state can be
fetched via a polling endpoint specified in
`document_partitioning.dynamic_polling_fallback`.

### 5.4.  Partitioning Metadata

The `document_partitioning` object links AIP-Static and AIP-Dynamic:

```json
{
  "document_partitioning": {
    "static_ref": "https://registry.example.com/agents/<agent-id>/static",
    "static_etag": "W/\"v1.3\"",
    "dynamic_ssf_stream": "https://ssf.example.com/streams/<stream-id>",
    "dynamic_polling_fallback": "https://registry.example.com/agents/<agent-id>/dynamic",
    "cache_policy": {
      "static_max_age_seconds": 3600,
      "dynamic_delivery": "push_preferred"
    }
  }
}
```

Field definitions:

static_ref (REQUIRED):
:  The HTTPS URL where AIP-Static is served.

static_etag (REQUIRED):
:  An ETag [RFC 7232] that uniquely identifies the current version
of AIP-Static.  Consumers MUST use this for conditional requests.

dynamic_ssf_stream (REQUIRED):
:  The OpenID SSF event stream URL for receiving AIP-Dynamic events.

dynamic_polling_fallback (OPTIONAL):
:  A fallback polling endpoint for AIP-Dynamic if event streaming
is not available.

cache_policy (REQUIRED):
:  Cache behavior recommendations.  `static_max_age_seconds`
indicates the maximum recommended cache duration for AIP-Static.
`dynamic_delivery` indicates the preferred delivery method:
"push_preferred" (use event streams), "poll_only" (use polling
fallback), "push_required" (push is mandatory).

### 5.5.  Caching and Consistency

Implementations SHOULD cache AIP-Static documents according to the
`cache_policy.static_max_age_seconds` value.  Cache keys MUST be
based on the `agent_id`.  Cache invalidation SHOULD use the ETag
mechanism with conditional requests.

For consistency, implementations MUST:

(a) Validate the AIP-Static signature before trusting any of its
contents.

(b) Subscribe to the AIP-Dynamic event stream to receive
real-time state updates.

(c) When receiving an AIP-Dynamic event that indicates a state
change affecting authorization decisions (e.g., credential
expiration, trust level decrease, lifecycle state change),
implement appropriate safeguards (e.g., revoke sessions, require
re-authorization).

(d) Implement a fallback polling mechanism if event streaming is
unavailable.  Polling interval SHOULD be no more than twice
the `credential_lifecycle.revocation.revocation_check_interval`.

(e) Handle network partitions gracefully: if AIP-Dynamic updates
cannot be received, the agent SHOULD be treated as having a
degraded trust level until connectivity is restored.

(f) Validate all AIP-Dynamic event signatures using the same
verification key used for AIP-Static unless a separate key is
specified in the event payload.

## 6.  AIP Lifecycle State Machine

### 6.1.  States

An AIP document transitions through the following states during its
lifecycle:

Created:
:  The AIP document has been generated but has not yet received
all required endorsements and completed initial attestation.
In this state, the agent MUST NOT be used for any operations.
This is a transient initialization state.  See Section 4.13.

Active:
:  The AIP document has been fully endorsed and attested, and the
agent is authorized to operate within its declared capabilities.
This is the normal operating state.  See Section 4.13.

Suspended:
:  The agent has been temporarily suspended due to a detected
anomaly, policy violation, integrity failure, or explicit
administrative action.  In this state, ongoing operations are
allowed to complete gracefully, but new operations MUST be
rejected.  The agent MAY return to the Active state after the
suspension cause is resolved.  See Section 4.13.

Revoked:
:  The AIP document has been permanently revoked.  This is an
irreversible terminal state.  All credentials MUST be
invalidated immediately.  All ongoing operations SHOULD be
terminated where possible.  See Section 4.13.

Decommissioned:
:  The agent has been formally decommissioned according to the
decommissioning procedure documented in
`governance.lifecycle_policy.decommission_procedure`.  This is
an irreversible terminal state reached after a planned shutdown
process.  See Section 4.13.

### 6.2.  State Transitions

The following state transitions are defined:

Created -> Active:
:  Triggered when:
1. The AIP document receives at least one valid endorsement from a
trusted authority for `owner_binding` and `integrity`
2. Initial attestation succeeds with `attestation_results.verified=true`
3. `trust_level` is computed and is not "compromised"

Active -> Suspended:
:  Triggered by any of the following conditions:
(a) Trust score falls below the suspension threshold and
`trust_level` degrades.
(b) Integrity verification fails at a checkpoint or is detected
on-demand.
(c) Policy violation detected (e.g., accessing restricted
capabilities without approval).
(d) Administrative action by sponsor or security team via
lifecycle management API.
(e) Failure to complete attestation before
`attestation.next_attestation_deadline`.
(f) Behavioral anomaly detection triggers a security alert.

Suspended -> Active:
:  Triggered when the suspension cause is resolved:
(a) Trust score recovers above the activation threshold and
`trust_level` is restored.
(b) Integrity verification succeeds on re-check.
(c) Policy violation is remediated and verified.
(d) Administrative action (sponsor approval).
(e) Attestation succeeds before a grace period expires.
When returning to Active, the trust score SHOULD be reset
to a conservative baseline (not the pre-suspension level).

Active/Suspended -> Revoked:
:  Triggered by any of the following conditions:
(a) Explicit revocation by the owner or sponsor via lifecycle API.
(b) Critical security incident (e.g., credential compromise
detected, `trust_level` becomes "compromised").
(c) Failure to attend to suspension within a defined grace period.
(d) Regulatory or legal requirement.
(e) Emergency kill switch activation.
This transition MUST be logged with the revocation reason and
MUST trigger immediate credential invalidation.

Active -> Decommissioned:
:  Triggered by a planned decommissioning process.  The agent
MUST complete all ongoing operations, release all held resources,
and generate a final audit log.  The transition to Decommissioned
MUST be preceded by:
1. Notification to all dependent systems
2. Transition to Suspended (if not already suspended) to allow
graceful shutdown
3. Completion of all in-flight operations
4. Final credential invalidation
This transition is NOT permitted from Revoked under normal
circumstances (security revocations should remain as Revoked for
audit purposes).

Revoked -> Decommissioned:
:  MAY be performed after a revocation to formally close the
agent's lifecycle records.  This transition requires:
(a) Root cause analysis completion
(b) Security remediation verification
(c) Stakeholder approval
(d) Final audit record generation
No additional conditions are REQUIRED for administrative
decommissioning after sufficient time has passed.

Decommissioned:
:  Terminal state. No transitions are permitted from Decommissioned.

### 6.3.  Transition Triggers

State transitions are triggered by events from the following sources:

(a) Lifecycle Management API:  Administrative operations through
the Identity Server's lifecycle management interface.

(b) Trust Engine:  Trust score changes detected by the trust
evaluation service, resulting in `trust_level` changes.

(c) Integrity Monitor:  Integrity verification failures or
configuration changes.

(d) Attestation Service:  Attestation success or failure events,
including deadline expiration.

(e) Policy Engine:  Policy violation detections from runtime monitoring.

(f) Emergency Kill Switch:  Activation of the emergency revocation
endpoint.

(g) Decommissioning Workflow:  Automated or manual decommissioning
procedure execution.

(h) Owner/Sponsor Action:  Direct administrative action by authorized
personnel.

### 6.4.  Protocol Behavior per State

The behavior of protocols consuming AIP MUST vary based on the
`lifecycle_state`:

Created:
:  Authorization Servers MUST reject all authorization requests.
Resource Servers MUST reject all access requests.  The AIP
document SHOULD be treated as non-existent for authorization
purposes.  Any ongoing operations from this agent MUST be
terminated immediately.

Active:
:  Normal operation.  Authorization Servers MAY evaluate requests
based on the agent's trust level, declared capabilities, and
governance policies.  Resource Servers MAY grant access subject
to their authorization policies and the agent's `trust_level`.

Suspended:
:  Authorization Servers MUST suspend ongoing authorization flows
but MAY allow in-flight operations to complete (grace period).
New authorization requests MUST be rejected.  Resource Servers
SHOULD accept requests with valid AOATs issued before the
suspension timestamp but SHOULD reject new requests.  The
agent MAY be allowed to read its own state but not perform
actions affecting external resources.

Revoked:
:  All authorization requests MUST be rejected immediately.
Resource Servers MUST invalidate any cached permissions.
The `credential_lifecycle.revocation.emergency_kill_switch`
endpoint SHOULD be called to propagate revocation to all
systems.  All ongoing operations MUST be terminated where
possible.  The agent MUST NOT be allowed to perform any
operations, including state reads.

Decommissioned:
:  Same protocol behavior as Revoked, but with different audit
semantics (decommissioning rather than security revocation).
The agent's identity MUST be removed from all operational
systems, but its records SHOULD be preserved for audit purposes.

## 7.  AIP Discovery and Resolution Protocol

### 7.1.  Overview

The AIP Discovery and Resolution Protocol enables systems to
discover where AIP documents are stored for a given `agent_id` and
to retrieve those documents.  The protocol is designed to support
both same-domain and cross-domain resolution without requiring a
centralized global registry.

The protocol follows a three-step discovery flow:

1.  Extract the trust domain from the `agent_id`.
2.  Query the trust domain's well-known configuration endpoint.
3.  Query the AIP Registry endpoint identified in step 2.

For cross-domain resolution, the protocol optionally uses WebFinger
[RFC 7033] as a federation mechanism.

### 7.2.  Well-Known Configuration Endpoint

Each trust domain MUST expose a well-known configuration endpoint
at:

```
https://<trust-domain>/.well-known/aip-configuration
```

This endpoint MUST be accessible via HTTPS (see Section 12.1) and
MUST support CORS for cross-domain requests.

The response is a JSON document:

```json
{
  "version": "1.0",
  "registry_endpoint": "https://registry.<trust-domain>/agents/",
  "cross_domain_federation": {
    "enabled": true,
    "protocol": "webfinger+aip",
    "trusted_domains": ["partner.example.org"]
  },
  "supported_query_params": ["agent_id", "agent_type", "owner_id"],
  "cache_control": {
    "static_ttl_seconds": 3600,
    "dynamic_subscription_endpoint": "https://ssf.<trust-domain>/streams/"
  },
  "jwks_uri": "https://auth.<trust-domain>/.well-known/jwks.json",
  "issuer": "wimse://<trust-domain>",
  "aip_version_supported": ["1.0"]
}
```

Field definitions:

version (REQUIRED):
:  The version of the aip-configuration format.  Currently "1.0".

registry_endpoint (REQUIRED):
:  The base URL of the AIP Registry.  AIP documents are accessed
by appending the agent_id (URL-encoded) to this URL.

cross_domain_federation (REQUIRED if federation is supported):
:  Federation configuration.  `protocol` specifies the federation
protocol.  The value "webfinger+aip" indicates that WebFinger
is used with a custom resource type for AIP discovery.

supported_query_params (REQUIRED):
:  Query parameters supported by the AIP Registry API.

cache_control (RECOMMENDED):
:  Cache policy recommendations for this domain.

jwks_uri (REQUIRED):
:  The JWKS endpoint [RFC 7517] for verifying AIP document
signatures from this trust domain.

issuer (REQUIRED):
:  The issuer identifier for this trust domain.  This MUST match
the `issuer` field in AIP `document_metadata`.

aip_version_supported (REQUIRED):
:  Array of AIP specification versions supported by this domain.
Consumers MUST check this array before attempting to use AIP
documents.

### 7.3.  AIP Registry API

The AIP Registry API provides endpoints for retrieving AIP
documents.  All endpoints MUST be accessible via HTTPS (Section
12.1) and MUST implement rate limiting (Section 12.11).

#### 7.3.1.  Retrieve AIP-Static

```
GET {registry_endpoint}/{url-encoded-agent-id}
```

Headers:
-  Accept: application/aip+json
-  If-None-Match: {static_etag} (for conditional requests)

Response (200 OK):
```json
{
  "aip_static": {
    "profile_version": "1.0",
    "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
    "agent_type": "coding"
    /* ... other AIP-Static fields ... */
  },
  "signature": {
    "protected": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVhdCtqd3QifQ...",
    "signature": "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "header": {
      "alg": "RS256",
      "kid": "key-2026-01"
    }
  },
  "document_metadata": {
    "document_id": "urn:uuid:a1b2c3d4...",
    "issued_at": "2026-03-07T10:00:00Z",
    "expires_at": "2026-03-08T10:00:00Z"
  }
}
```

The `signature` is a JWS [RFC 7515] over the `aip_static` object.

Response codes:
-  200 OK:  AIP-Static document found.
-  304 Not Modified:  Conditional request match, document not changed.
-  404 Not Found:  Agent not found.
-  410 Gone:  Agent was decommissioned.
-  429 Too Many Requests:  Rate limit exceeded.
-  500 Internal Server Error:  Server error (client MAY retry with exponential backoff).

#### 7.3.2.  Retrieve AIP-Dynamic

AIP-Dynamic is retrieved via event stream subscription.  The stream
endpoint is specified in AIP-Static's `document_partitioning.dynamic_ssf_stream`.

For polling fallback:

```
GET {registry_endpoint}/{url-encoded-agent-id}/dynamic
```

Headers:
-  Accept: application/aip-dynamic+json

Response (200 OK):
```json
{
  "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
  "last_updated": "2026-03-07T10:00:00Z",
  "trust_level": "verified",
  "lifecycle_state": "active",
  "credential_lifecycle": {"primary_credential": {"type": "WIT"}},
  "attestation": {"format": "urn:ietf:params:oauth:token-type:eat"},
  "behavioral_anomalies": []
}
```

### 7.4.  Resolution Flow

The complete resolution flow is:

1.  Client receives an `agent_id` (e.g., in an AOAT claim).

2.  Client extracts the trust domain from the `agent_id`:
    "wimse://trust.example.com/agents/..." -> "trust.example.com"

3.  Client queries the well-known endpoint:
    ```
    GET https://trust.example.com/.well-known/aip-configuration
    ```

4.  Client validates the response:
    -  Checks HTTPS certificate validity
    -  Verifies that `aip_version_supported` includes the client's
       supported version
    -  Extracts the `registry_endpoint` and `jwks_uri`

5.  Client retrieves AIP-Static:
    ```
    GET https://registry.trust.example.com/agents/<agent-id>
    ```

6.  Client validates the JWS signature:
    -  Fetches the JWKS from `jwks_uri`
    -  Verifies the signature using the key identified by `kid`
    -  Checks that `document_metadata.issuer` matches the trust domain

7.  Client validates document metadata:
    -  Checks that `document_metadata.expires_at` is in the future
    -  Verifies that `nonce` has not been seen before (Section 12.3)

8.  Client extracts the `dynamic_ssf_stream` URL and subscribes to
    receive AIP-Dynamic updates.

9.  Client (optionally) fetches AIP-Dynamic immediately via the
    polling fallback endpoint.

### 7.5.  Cross-Domain Resolution via WebFinger

For cross-domain resolution, the protocol uses WebFinger [RFC 7033]
with a custom resource type.

#### 7.5.1.  WebFinger Query

```
GET https://<trusted-domain>/.well-known/webfinger?
  resource=urn:aip:wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000&
  rel=urn:ietf:params:aip:profile
```

Parameters:
-  resource:  The agent_id prefixed with "urn:aip:" to avoid URI
   scheme conflicts.
-  rel:  The relationship type for AIP profile discovery.

The resource parameter uses "urn:aip:" prefix instead of "aip:" to
avoid potential conflicts with registered URI schemes and to ensure
proper encoding as a URN.

#### 7.5.2.  WebFinger Response

```json
{
  "subject": "urn:aip:wimse://trust.example.com/agents/...",
  "links": [
    {
      "rel": "urn:ietf:params:aip:profile",
      "href": "https://registry.trust.example.com/agents/<agent-id>",
      "titles": { "en": "AIP Profile" }
    },
    {
      "rel": "urn:ietf:params:aip:dynamic",
      "href": "https://ssf.trust.example.com/streams/<stream-id>",
      "titles": { "en": "AIP Dynamic Events" }
    }
  ],
  "expires": "2026-03-08T10:00:00Z"
}
```

The `href` values point to the AIP Registry endpoints in the
trusted domain.  The `expires` field indicates when this WebFinger
response should be considered stale.

### 7.6.  Error Handling and Fallback

Implementations MUST handle the following error scenarios:

(a) Well-Known Endpoint Not Found (404):
-  The trust domain may not support AIP
-  Client SHOULD fall back to direct WIT-based authentication
-  Client SHOULD log this as a configuration error

(b) AIP Registry Unavailable (50x):
-  Client MAY retry with exponential backoff
-  Maximum retry attempts: 3
-  If unsuccessful, client MAY fall back to cached AIP data
(if available and not expired)

(c) Signature Verification Failed:
-  Client MUST reject the AIP document
-  Client SHOULD log a security event
-  Client MAY attempt to fetch a fresh JWKS and retry once

(d) Version Mismatch:
-  If `aip_version_supported` does not include the client's
version, client MUST reject the document
-  Client SHOULD log an interoperability issue
-  Client MAY attempt to use an older supported version if
backward compatible

(e) Cross-Domain Resolution Failure:
-  If WebFinger returns 404 or 403, cross-domain resolution is
not supported
-  Client SHOULD fall back to same-domain resolution only
-  Client SHOULD not attempt cross-domain operations

(f) Rate Limit Exceeded (429):
-  Client MUST respect the Retry-After header if present
-  Default backoff: 60 seconds
-  Client SHOULD implement per-domain rate limiting

## 8.  Delegation Chains and Multi-Agent Identity

### 8.1.  Delegation Chain Structure

In multi-agent scenarios, authority flows from the original human
user through one or more intermediate agents to the currently
acting agent.  This provenance is recorded in the
`delegation_chain` array (see Section 4.5.4).

Each delegation step MUST be represented as a JSON object with the
following fields:

iss (REQUIRED):
:  The issuer of this delegation step.  This is typically the
`agent_id` of the delegator or the URI of the Authorization
Server that mediated the delegation.

sub (REQUIRED):
:  The subject of this delegation step.  This is the `agent_id`
of the delegator.

aud (REQUIRED):
:  The audience of this delegation step.  This is the `agent_id`
of the delegatee.

delegated_at (REQUIRED):
:  RFC 3339 timestamp when this delegation was created.

scope (REQUIRED):
:  Space-delimited list of scopes delegated.  Each scope MUST be
a subset of the delegator's available scopes.

purpose (REQUIRED):
:  Human-readable description of the delegation purpose.

constraints (OPTIONAL):
:  Additional constraints on the delegation.

jti (REQUIRED):
:  Unique identifier for this delegation step.  MUST be a URN UUID
[RFC 4122].  Used for deduplication and audit.  The jti MUST be
globally unique (not just unique within a chain).

### 8.2.  Derived AIP and Scope Narrowing

When Agent A delegates to Agent B, Agent B receives a Derived AIP.
The Derived AIP MUST satisfy the following requirements:

(a) Binding Proof:  The Derived AIP MUST include a cryptographic
binding to the parent AIP.  This is done via the
`delegation_chain` array, which MUST include the delegation
step from Agent A to Agent B.

(b) Scope Narrowing:  The `capabilities.declared` array in the
Derived AIP MUST be a strict subset of the parent's declared
capabilities.  This is the lattice-theoretic "meet" operation
— the derived capability set is the greatest lower bound of
the parent capability set and the specific needs of the
delegation.

(c) Delegation Depth Constraint:  The depth of the delegation
chain (length of `delegation_chain`) MUST NOT exceed the
`delegation_authority.max_delegation_depth` of the root AIP.

(d) Resource Constraints:  Any resource constraints in the
delegation step MUST be enforced by the Derived AIP.  For
example, if the delegation constrains `file.read` to
`/workspace/project/**`, the Derived AIP's `file.read`
capability MUST have a `scope` that is a subset of this pattern.

(e) Expiration:  Derived AIPs MUST have a validity period that
is no longer than the parent AIP's remaining validity period.

(f) Trust Level Inheritance:  The Derived AIP's `trust_level`
MUST NOT exceed the parent's `trust_level`.  Typically, the
derived trust level SHOULD be one level lower than the parent
due to increased complexity and reduced direct oversight.

### 8.3.  Delegation Depth Control

The `max_delegation_depth` field in `delegation_authority`
controls how deep delegation can go from a given AIP.

A delegation depth of 0 (with `can_delegate: true`) means the
agent can delegate to direct children, but those children cannot
delegate further.

A delegation depth of 2 allows:
Owner (root) -> Agent A (depth 0) -> Agent B (depth 1) -> Agent C (depth 2)

Agent C cannot delegate further because it would exceed depth 2.

Implementations MUST enforce delegation depth limits by checking
the length of the `delegation_chain` array before accepting any
delegated authorization.  The chain length MUST NOT exceed
`max_delegation_depth + 1` (to account for the root agent).

### 8.4.  Chain Validation Rules

Before accepting a delegation claim, implementations MUST validate
the delegation chain according to the following rules:

1.  Sequential Order:  The `delegated_at` timestamps MUST be in
    strictly increasing order.

2.  Issuer Trust:  Each `iss` in the chain MUST be recognized as a
    trusted issuer for the respective step.  For delegation steps
    mediated by Authorization Servers, the `iss` MUST be the AS URI.
    For agent-to-agent delegation, the `iss` MUST be the delegator's
    `agent_id`, and the delegation MUST be signed by the delegator.

3.  Audience Matching:  For delegation step N, the `aud` MUST match
    the `sub` of delegation step N+1.  This ensures a continuous
    chain of authority.

4.  Scope Narrowing:  Each step's `scope` MUST be a subset of the
    previous step's scope.  The final scope MUST be a subset of
    the agent's declared capabilities.

5.  Constraints Execution:  All constraints at each step MUST be
    enforced in subsequent steps.  If a delegation constrains a
    capability to a specific resource pattern, all downstream
    capabilities MUST respect that constraint.

6.  Signature Verification:  Each delegation step MUST be
    cryptographically signed.  For AS-mediated steps, the signature
    MUST be verifiable using the AS's signing key.  For agent-to-
    agent steps, the signature MUST be verifiable using the
    delegator's signing key (derived from the delegator's AIP).

7.  Policy Evaluation:  The chain MUST be evaluated against the
    Authorization Server's delegation policy.  The policy MAY impose
    additional restrictions on delegation (e.g., require explicit
    approval for delegation of high-risk capabilities).

8.  JTI Uniqueness:  Each `jti` in the delegation chain MUST be
    globally unique.  Implementations MUST detect duplicate JTIs
    within the same chain or across previously validated chains
    (to prevent replay attacks).

9.  Chain Length:  The length of the delegation chain MUST NOT
    exceed the `max_delegation_depth` of any ancestor AIP.

10. Circular Delegation:  Implementations MUST detect cycles in
    delegation chains.  A chain that revisits an `agent_id` is
    invalid.

11. Expiration:  Each delegation step MAY include an expiration
    time.  If present, the step MUST be ignored if the current time
    exceeds the expiration.

## 9.  Cross-Domain AIP Projection

### 9.1.  Projection Levels

When an AIP document is shared across trust domain boundaries, it
is often inappropriate to disclose the full document due to
privacy, security, or competitive concerns.  AIP supports three
projection levels:

Minimal Projection:
:  Reveals only the minimum information necessary for basic
identity recognition and trust assessment:

-  agent_id
-  agent_type
-  capabilities.declared (capability identifiers only, without
   scope details or risk levels)
-  attestation.verification_endpoint (for cross-domain
   attestation verification)
-  lifecycle_state
-  trust_level (if not "unverified")

The `owner_binding.owner_id`, `governance.sponsor`,
`governance.compliance_requirements`, and detailed
`capabilities.declared` entries are NOT included.

Standard Projection:
:  Reveals the Minimal Projection plus:

-  owner_binding (but without `owner_id`; reveals only binding
   model and binding proof)
-  integrity.composite_hash
-  governance.risk_classification
-  governance.compliance_requirements (optional, based on
   regulatory context)
-  credential_lifecycle.expiration information
-  document_metadata.issuer and document_metadata.expires_at

Full Projection:
:  Reveals the complete AIP document.  MUST only be used when
there is a pre-existing high-trust relationship between the
domains (e.g., organizational partnership, joint compliance
audit).

### 9.2.  Projection Negotiation Protocol

The projection level SHOULD be negotiated between the requesting
and asserting domains.  The requesting domain sends a projection
negotiation request:

```
POST https://<trust-domain>/.well-known/aip-projection
Content-Type: application/aip-projection-request+json

{
  "requested_level": "standard",
  "requested_fields": ["agent_type", "capabilities", "delegation_chain"],
  "requester_trust_evidence": "<JWS with requester's credentials>",
  "requester_purpose": "cross_org_task_delegation",
  "agent_id": "<agent_id to project>",
  "requester_domain": "wimse://requester.example.com",
  "nonce": "proj-abc-123"
}
```

Field definitions:

requested_level (REQUIRED):
:  The desired projection level: "minimal", "standard", or "full".

requested_fields (REQUIRED):
:  Array of fields the requester needs.  If a requested field is
not available at the requested level, the request MAY be
upgraded to the next level or rejected based on policy.

requester_trust_evidence (REQUIRED):
:  Cryptographic evidence of the requester's identity and authority.
This MUST be a JWS signed by the requester domain's Identity Server.

requester_purpose (RECOMMENDED):
:  Description of why this projection is needed.  The asserting
domain's policy MAY require this for certain projection levels.

agent_id (REQUIRED):
:  The `agent_id` for which projection is requested.

requester_domain (REQUIRED):
:  The trust domain of the requester.  This is used for trust
evaluation and policy application.

nonce (REQUIRED):
:  A unique nonce for this request to prevent replay attacks.
MUST be at least 128 bits of entropy.

Response (200 OK):
```json
{
  "level_granted": "standard",
  "fields_included": ["agent_type", "capabilities", "delegation_chain"],
  "excluded_fields": ["owner_binding.owner_id", "governance.sponsor"],
  "aip_projection": {
    "agent_id": "wimse://trust.example.com/agents/...",
    "agent_type": "coding",
    "capabilities": {"declared": [{"capability": "file.read"}]},
    "lifecycle_state": "active"
  },
  "projection_nonce": "proj-xyz-456",
  "expires_at": "2026-03-07T11:00:00Z"
}
```

If the projection request cannot be granted:
-  403 Forbidden:  Projection request denied (insufficient trust,
   policy violation).
-  417 Expectation Failed:  Some requested fields unavailable,
   level adjustment suggested in the `level_granted` field (which
   MUST be lower than requested for this case).
-  429 Too Many Requests:  Rate limit exceeded.

### 9.3.  Field Visibility Rules

This specification provides a reference implementation of a
visibility policy.  Implementations MAY define their own policies
but MUST NOT disclose more information than the reference policy
allows at each projection level.

The reference visibility rules:

| Field Path                        | Minimal | Standard | Full |
|-----------------------------------|---------|----------|------|
| agent_id                          | Full    | Full     | Full |
| agent_type                        | Yes     | Yes      | Yes |
| agent_model                       | No      | Yes      | Yes |
| display_name                      | No      | Yes      | Yes |
| owner_binding.owner_id            | No      | No       | Yes |
| owner_binding.binding_*           | No      | Yes      | Yes |
| capabilities.declared             | Id only | Full     | Full |
| capabilities.restricted           | No      | Id only  | Yes |
| autonomy_level                    | No      | Yes      | Yes |
| attestation.verification_endpoint| Yes     | Yes      | Yes |
| attestation.token                 | No      | No       | Yes |
| integrity.composite_hash          | No      | Yes      | Yes |
| governance.sponsor                | No      | No       | Yes |
| governance.compliance             | No      | Optional | Yes |
| governance.risk_classification    | No      | Yes      | Yes |
| trust_level                       | Partial*| Yes      | Yes |
| lifecycle_state                   | Yes     | Yes      | Yes |
| credential_lifecycle              | Expiry  | Full     | Full |
| observability.audit_log_endpoint  | No      | No       | Yes |
| document_metadata.issuer          | No      | Yes      | Yes |
| document_metadata.expires_at      | No      | Yes      | Yes |
| extensions                        | Filtered | Filtered| Full |

*In Minimal projection, only show trust_level if it is "compromised".

"Id only" means only the `capability` identifier is included,
without `scope`, `risk_level`, or `mcp_tool_ref`.

"Filtered" in extensions means only extensions with a
`visibility` policy set to "minimal" or "standard" are included.

Implementations MUST allow domain-specific policy to override
these reference rules, but MUST NOT be less restrictive than
the reference rules.

## 10.  Integrity Verification Model

### 10.1.  Core Invariants and Controlled Mutables

AIP recognizes that not all configuration changes are equally
suspicious.  Some configuration aspects (e.g., security policies)
should never change without explicit re-authorization.  Other
aspects (e.g., dynamically loaded tools) MAY change as part of
normal operation.

The `integrity` object is structured into two categories:

Core Invariants:
:  Configuration elements that MUST NOT change during the agent's
session without triggering a security event.  These include:

-  system_config_hash:  Hash of the core security configuration
   (e.g., permission boundaries, security policies).
-  security_policy_hash:  Hash of the agent's security policy
   (e.g., allowed operations, risk thresholds).

Changes to core invariants MUST trigger a security event and
typically require re-verification or re-authorization.  In
production deployments, changes to core invariants SHOULD
require explicit sponsor approval through the Lifecycle
Management API.

Controlled Mutables:
:  Configuration elements that MAY change within predefined rules.
These include:

-  tools_config.mutation_policy:  One of "append_only" (new
   tools MAY be added but not removed), "version_tracked"
   (changes are allowed but MUST be versioned), "strict" (no
   changes allowed).
-  prompt_template.mutation_policy:  Similar to tools_config,
   but with an additional semantic drift parameter.
-  prompt_template.max_drift_from_baseline:  A value between
   0.0 and 1.0 indicating the maximum allowed semantic drift
   from the baseline prompt.  Drift is measured using embedding
   similarity.

Changes to controlled mutables MUST:
-  Comply with the specified `mutation_policy`
-  Include change audit records
-  Be logged to the `observability.audit_log_endpoint`

### 10.2.  Verification Triggers

Integrity verification MUST be triggered in the following scenarios:

(a) Agent Startup:  When the agent process starts, integrity MUST
be verified before any operations are permitted.

(b) Permission Escalation:  When the agent requests access to a
higher-risk capability than it has previously accessed,
integrity MUST be re-verified.

(c) Configuration Change:  When any component of the agent's
configuration changes (detected via file system watchers or
runtime events), integrity MUST be re-verified.

(d) Trust Score Decrease:  When the agent's trust score decreases
by more than a configured threshold (e.g., 0.2), integrity
MUST be re-verified to rule out configuration tampering as the
cause.

(e) Periodic Verification:  Integrity MUST be re-verified at a
regular interval.  The interval SHOULD be synchronized with
the attestation deadline to avoid redundant verification
cycles.

(f) Delegation Chain Update:  When a new delegation is added to
the delegation chain, integrity MUST be re-verified to ensure
the new agent is operating within expected parameters.

### 10.3.  Semantic Drift Detection

For prompt templates, exact hash comparison MAY be too strict,
especially when the agent uses dynamic prompts or context-aware
prompt construction.

AIP supports semantic drift detection using embedding-based
similarity:

1.  The baseline prompt template is embedded using a standardized
    embedding model (e.g., a model from the OpenAI Embeddings API
    or similar).

2.  When the prompt template changes, the new template is embedded
    using the same model.

3.  The cosine similarity between the baseline and new embeddings
    is calculated.

4.  If the similarity is below the threshold
    (1.0 - max_drift_from_baseline), the drift is considered
    excessive and a security event is triggered.

Example: If `max_drift_from_baseline` is 0.3, the similarity
threshold is 0.7. Similarity of 0.85 is acceptable; similarity of
0.65 triggers an event.

Security Considerations for Semantic Drift:

Implementations MUST be aware of the security implications of
semantic drift detection:

1.  Embedding Model Supply Chain:  The embedding model itself is
    a potential attack vector.  Implementations SHOULD:
    -  Use models from trusted sources
    -  Verify model integrity before use
    -  Consider using air-gapped models for high-security
       deployments

2.  Adversarial Drift:  Sophisticated attackers MAY craft prompts
    that maintain high semantic similarity while altering behavior
    in subtle ways.  Implementations SHOULD:
    -  Combine semantic drift detection with other integrity checks
    -  Monitor for behavioral anomalies that don't trigger drift
       detection
    -  Consider setting conservative drift thresholds for
       high-risk agents

3.  Model Versioning:  The embedding model MAY be updated over
    time, which can change similarity scores.  Implementations SHOULD:
    -  Version the embedding model used for baseline creation
    -  Store the model version with the baseline
    -  Recompute baselines when the model is updated

4.  False Positives/Negatives:  Semantic drift detection is not
    perfect.  Implementations SHOULD:
    -  Treat drift alerts as signals, not definitive proof of
       attacks
    -  Require human review for high-severity drift alerts
    -  Maintain feedback loops to improve detection accuracy

The embedding model specification is out of scope for this
specification.  Implementations SHOULD document the model used
and ensure consistency across verification cycles.

## 11.  Integration with Existing Protocols

### 11.1.  Integration with WIMSE (WIT/WPT)

AIP is designed to coexist with WIMSE Workload Identity Tokens
[WIT] and Workload Proof Tokens [WPT].

Relationship:

-  WIT provides the runtime credential that the agent presents
   when accessing resources.  The `agent_id` in AIP uses the same
   URI format as the SPIFFE ID in a WIT.

-  AIP provides the metadata describing the agent that issued the
   WIT.  Resource servers can use the AIP to make richer trust
   decisions beyond what the WIT alone conveys.

Integration Pattern:

When an agent authenticates using a WIT, the WIT MAY include an
extension claim referencing the AIP:

```json
{
  "iss": "wimse://trust.example.com",
  "sub": "spiffe://trust.example.com/agents/agent-123",
  "aip_ref": "https://registry.example.com/agents/agent-123",
  "aip_version": "1.0"
}
```

The resource server retrieves the AIP using the `aip_ref` and
uses the metadata for authorization decisions.

### 11.2.  Integration with OIDC and OIDC-A

AIP integrates with OpenID Connect [OIDC-Core] and OpenID Connect
for Agents [OIDC-A].

Claim Mapping:

AIP fields can be mapped to OIDC-A claims:

| AIP Field Path                            | OIDC-A Claim              |
|-------------------------------------------|---------------------------|
| agent_type                                | agent_type                |
| agent_model                               | agent_model               |
| agent_provider                            | agent_provider            |
| agent_instance_id                         | agent_instance_id         |
| owner_binding.delegation_chain            | delegation_chain           |
| capabilities.oidc_a_format                | agent_capabilities        |
| attestation.format                        | agent_attestation.format   |
| attestation.token                         | agent_attestation.token    |
| attestation.timestamp                     | agent_attestation.time     |
| attestation.verification_endpoint         | agent_attestation.endpoint |
| framework.attestation_formats_supported   | attestation_formats_supported|
| framework.delegation_methods_supported   | delegation_methods_supported|
| framework.models_supported                | agent_models_supported     |

Token Integration:

AIP information can be embedded in the OIDC ID Token or Access
Token as claims.  Two approaches are supported:

Approach 1 — Inline Claims:
All relevant AIP fields are included as claims in the token.
This increases token size but avoids separate document fetch.
This approach is suitable for:
-  Low-bandwidth environments
-  Scenarios where the AIP contains minimal data
-  Tokens with short expiration times

Approach 2 — Reference Claim:
Only the `aip_ref` is included in the token.  The consumer fetches
the full AIP when needed.  This keeps tokens compact and allows
AIP updates without requiring new tokens.
This approach is suitable for:
-  High-bandwidth environments
-  Scenarios where the AIP contains extensive data
-  Long-lived tokens

Discovery Integration:

AIP's `observability.discovery_endpoints` aligns with OIDC-A's
discovery mechanism.  The `.well-known/aip-configuration` endpoint
can be co-located with the OIDC discovery endpoint at
`/.well-known/openid-configuration`.

### 11.3.  Integration with draft-liu AOAT Framework

The AOAT framework [I-D.liu-agent-operation-authorization]
defines an `agent_identity` claim with seven baseline fields.

Mapping:

| AIP Field Path                              | AOAT agent_identity Field |
|---------------------------------------------|---------------------------|
| profile_version                             | version                   |
| agent_id (UUID portion)                      | id                        |
| owner_binding.owner_id                       | issuedTo                  |
| agent_id (trust domain portion)              | issuer                    |
| credential_lifecycle.primary_credential.issued_at | issuanceDate          |
| credential_lifecycle.primary_credential.issued_at | validFrom             |
| credential_lifecycle.primary_credential.expires_at | expires              |
| framework.name + agent_type                  | issuedFor.client          |
| attestation.attestation_results.platform.namespace | issuedFor.clientInstance |
| document_metadata.issuer                    | (issuer extension)        |

Extended Integration:

The AOAT `agent_identity` claim can be extended with an `aip_ref`
field:

```json
{
  "agent_identity": {
    "version": "1.0",
    "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "issuer": "wimse://trust.example.com",
    "issuedTo": "user@example.com",
    "issuedFor": {
      "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
      "type": "VerifiableCredential"
    },
    "issuanceDate": 1714348800,
    "validFrom": 1714348800,
    "expires": 1714352400,
    "aip_ref": "https://registry.example.com/agents/550e8400..."
  }
}
```

Resource servers that support AIP can use the `aip_ref` to fetch
the full metadata.  Servers that do not support AIP fall back to
the baseline fields.

### 11.4.  Integration with MCP (Model Context Protocol)

AIP integrates with MCP [MCP] through the capability declaration
mechanism.

Capability Mapping:

AIP `capabilities.declared` entries can reference MCP tools:

```json
{
  "capability": "file.read",
  "scope": "/workspace/**",
  "risk_level": "low",
  "mcp_tool_ref": "filesystem/readFile"
}
```

When an agent calls an MCP tool, the MCP Server can use the
`mcp_tool_ref` to look up the corresponding AIP capability and
verify that the agent is authorized to use that tool.

Protocol Enhancement:

The MCP Tool Description format can be extended with an
`aip_capability` field:

```json
{
  "name": "readFile",
  "description": "Read a file",
  "aip_capability": "file.read",
  "required_autonomy_level": "human_on_the_loop",
  "required_trust_level": "verified"
}
```

The MCP Server enforces authorization based on the AIP by:
1.  Validating the agent's AIP-Static document
2.  Checking that the `aip_capability` is in `capabilities.declared`
3.  Verifying that the `scope` matches the requested resource
4.  Ensuring that `autonomy_level` and `trust_level` meet requirements

### 11.5.  Integration with A2A (Agent-to-Agent Protocol)

AIP supports agent-to-agent identity verification for protocols
like A2A.  This section describes integration with the A2A Agent
Card specification.

Handshake Integration:

In an A2A handshake, agents can exchange AIP references using the
Agent Card format:

```json
{
  "@context": ["https://www.w3.org/ns/activitystreams", "https://a2a.example/ns"],
  "type": "AgentCard",
  "id": "did:example:agent-a",
  "agent_id": "wimse://trust.example.com/agents/agent-a",
  "aip_ref": "https://registry.example.com/agents/agent-a",
  "aip_version": "1.0",
  "capabilities": ["file.read", "code.execute"]
}
```

Verification Flow:

1.  Agent A sends its Agent Card to Agent B
2.  Agent B fetches the AIP from `aip_ref`
3.  Agent B verifies the JWS signature
4.  Agent B evaluates the `trust_level`, `lifecycle_state`, and
    `capabilities`
5.  Agent B decides whether to proceed with interaction

Trust Establishment:

For peer-to-peer agent interactions, the following trust
establishment patterns are supported:

Direct Trust:
:  Agent B trusts Agent A's Identity Server based on a prior
relationship or federation agreement.

Federated Trust:
:  Agent B validates Agent A's Identity Server through a
federated trust chain (e.g., via a trust anchor bundle).

Peer Verification:
:  Agents exchange additional verification evidence (e.g.,
signed challenge-response) to establish mutual trust.

### 11.6.  Integration with OpenID Shared Signals Framework

AIP integrates with OpenID SSF [OIDC-SSF] for real-time event
distribution.  This section corrects the SSF integration description
from the -00 draft.

Event Types:

AIP defines the following SSF event types (in the CAEP profile):

-  urn:aip:event:trust-level-changed
-  urn:aip:event:credential-rotated
-  urn:aip:event:attestation-updated
-  urn:aip:event:lifecycle-state-changed
-  urn:aip:event:integrity-failure
-  urn:aip:event:policy-violation

Event Format:

AIP-Dynamic events MUST be JWS-wrapped according to the SSF
specification.  The event payload structure:

```json
{
  "iss": "wimse://trust.example.com",
  "aud": ["urn:aip:subscriber:system-x"],
  "iat": 1772978400,
  "jti": "urn:uuid:event-abc-123",
  "events": {
    "urn:aip:event:trust-level-changed": {
      "subject": "wimse://trust.example.com/agents/agent-123",
      "previous_level": "verified",
      "new_level": "trusted",
      "reason": "hardware_attestation_verified"
    }
  }
}
```

The `events` object contains one or more AIP event types.  Each
event includes:
-  `subject`:  The `agent_id` of the affected agent
-  Event-specific fields (e.g., `previous_level`, `new_level`)

Stream Configuration:

The `observability.ssf_config` object contains the stream IDs
for subscribing to these events:

```json
{
  "ssf_config": {
    "caep_stream_id": "stream-agent-caep-events-001",
    "risc_stream_id": "stream-agent-risc-events-001",
    "delivery_endpoint": "https://ssf.example.com/delivery"
  }
}
```

Subscription:

Subscribers MUST:
1.  Register with the SSF stream endpoint
2.  Provide authentication credentials (e.g., OAuth 2.0 access token)
3.  Specify which event types they want to receive
4.  Validate the JWS signature on each received event
5.  Verify that the `iss` matches the AIP document's `document_metadata.issuer`

## 12.  Security Considerations

### 12.1.  Transport Security

All AIP protocol endpoints, including:
-  Well-known configuration endpoint
-  AIP Registry API
-  AIP Resolution endpoints
-  Attestation verification endpoints
-  Integrity verification endpoints
-  Emergency revocation endpoints

MUST be accessible only via HTTPS [RFC 2818] with TLS 1.2 or
higher.  TLS 1.3 is RECOMMENDED.

Implementations MUST:
-  Validate server certificates using a trusted PKI
-  Implement certificate pinning for high-security deployments
-  Disable insecure protocols and cipher suites
-  Use strong cipher suites (e.g., TLS_AES_256_GCM_SHA384)
-  Implement HSTS headers for web-accessible endpoints

HTTP without TLS MUST NOT be used for AIP protocol communication.

### 12.2.  AIP Document Forgery

All AIP-Static documents MUST be cryptographically signed using
JWS [RFC 7515] with secure algorithms (RS256, ES256, or stronger).
The signature MUST cover the entire AIP-Static object payload.

Consumers MUST verify the signature before trusting any AIP
claims.  The verification process MUST include:

1.  Fetch the signing key from the Identity Server's JWKS endpoint
2.  Verify the JWS signature using the key identified by `kid`
3.  Check that the `alg` header matches a secure algorithm
4.  Verify that the `iss` claim matches the expected trust domain
5.  Check that the `exp` claim (if present) has not passed

The JWKS endpoint MUST be served via HTTPS with certificate
validation.  Consumers SHOULD cache JWKS responses with appropriate
TTL (typically 1 hour) and implement cache invalidation when keys
are rotated.

### 12.3.  Replay Attack Prevention

AIP documents and events are vulnerable to replay attacks.  To
prevent this, this specification implements multiple replay
prevention mechanisms:

1.  Document Nonce:  The `document_metadata.nonce` field MUST be
    unique for each issued AIP document version.  Consumers MUST
    maintain a cache of seen nonces for the issuer and reject
    documents with duplicate nonces.  The nonce cache SHOULD expire
    after the document's `expires_at` time.

2.  Event IDs:  Each AIP-Dynamic event MUST include a unique
    `event_id` (JTI).  Consumers MUST track event IDs to prevent
    event replay.  The event ID cache SHOULD have a reasonable TTL
    (e.g., 24 hours).

3.  Timestamp Validation:  Consumers MUST validate that
    `document_metadata.issued_at` and event timestamps are within
    an acceptable time window (e.g., 5 minutes) of the current time.
    Timestamps outside this window MUST be rejected.

4.  ETag-Based Freshness:  When fetching AIP-Static, consumers
    SHOULD use ETag-based conditional requests.  This ensures that
    they receive the latest version and prevents stale document
    reuse.

5.  One-Time Use Tokens:  For critical operations (e.g., emergency
    revocation), implementations MAY use one-time use tokens that
    expire immediately after use.

Nonce Management:

Identity Servers MUST:
-  Generate nonces with at least 128 bits of entropy
-  Ensure nonce uniqueness across all issued documents
-  Use a cryptographically secure random number generator
-  Track used nonces during their validity period

Consumers MUST:
-  Reject documents with missing or invalid nonces
-  Maintain nonce caches per-issuer
-  Implement nonce cache cleanup to prevent unbounded growth
-  Log nonce reuse attempts as security events

### 12.4.  Delegation Chain Attacks

Delegation chains are a potential attack vector.  Implementations
MUST enforce all validation rules defined in Section 8.4.

Specifically, implementations MUST protect against:

(a) Privilege Escalation:  Scope narrowing at each step MUST be
enforced.  A delegatee MUST NOT receive broader capabilities
than the delegator.

(b) Excessive Depth:  Delegation depth limits MUST be strictly
enforced.  Implementations MUST check the chain length against
`max_delegation_depth` at each validation.

(c) Circular Delegation:  Implementations MUST detect cycles in
delegation chains.  A chain that revisits an `agent_id` is
invalid.  Detection SHOULD be done by tracking visited agent
IDs during validation.

(d) Stale Delegations:  Delegation steps MUST include expiration
times.  Expired steps MUST be ignored.  Implementations SHOULD
cache delegation results with appropriate TTLs.

(e) JTI Collision:  Implementations MUST ensure that delegation
step JTIs are globally unique, not just unique within a chain.
Collision detection across chains prevents cross-chain replay
attacks.

(f) Signature Spoofing:  Each delegation step MUST be signed by
the delegator.  Implementations MUST verify the signature
using the delegator's public key (derived from the delegator's
AIP).

### 12.5.  Integrity Bypass

Attackers MAY attempt to bypass integrity checks by:

(a) Modifying the agent configuration and providing a forged
integrity hash.  This is prevented by the JWS signature on
AIP-Static, which covers the entire `integrity` object.

(b) Modifying the integrity verification endpoint to return
false positive results.  Implementations MUST use
certificate pinning for integrity verification endpoints and
SHOULD implement endpoint URL validation against the AIP's
declared endpoint.

(c) Exploiting timing windows between configuration change and
verification.  Implementations SHOULD perform verification
synchronously for critical operations and SHOULD monitor for
rapid configuration changes.

(d) Tampering with the `composite_hash` calculation.  The composite
hash MUST be computed using a cryptographic hash function
(SHA-256 or stronger) over a canonical representation of the
integrity data.  Implementations MUST verify that the
composite hash matches the independently computed value.

(e) Substituting the embedding model used for semantic drift
detection.  Implementations SHOULD pin the model version and
compute hashes of the model binary for integrity verification.

### 12.6.  Prompt Injection and Intent Deviation

AIP's integrity model provides defense against prompt injection
by detecting unexpected changes to prompt templates.  However,
sophisticated attacks MAY evade detection by:

(a) Keeping semantic similarity high while subtly altering behavior
through adversarial prompt engineering.

(b) Exploiting the `max_drift_from_baseline` threshold by crafting
prompts that are just below the threshold but still harmful.

Implementations SHOULD complement AIP integrity with:

(a) Intent Verification:  The Authorization Server SHOULD verify
that each operation request is semantically consistent with the
original user intent.  This can be done by:
-  Hashing the user's natural language request
-  Including the hash in the operation proposal
-  Verifying that subsequent operations reference this hash

(b) Behavioral Monitoring:  Real-time behavioral anomaly
detection (see Section 4.11) can detect subtle behavioral
shifts that integrity checks miss.  Implementations SHOULD:
-  Maintain a baseline of normal agent behavior
-  Monitor for deviations from baseline
-  Trigger security events when anomaly scores exceed thresholds

(c) Output Validation:  For high-risk operations, implement
output validation to ensure that agent-generated content meets
safety and policy requirements.

(d) Human-in-the-Loop:  For agents with `autonomy_level` of
"human_on_the_loop" or "human_in_the_loop", implement approval
workflows for operations that could result from prompt injection.

### 12.7.  Revocation Timeliness

Revocation MUST be timely to limit the impact of compromised
agents.  Implementations MUST:

(a) Use short-lived credentials as recommended by AIP lifecycle
policies (default rotation interval: PT1H).

(b) Implement push-based revocation via OpenID SSF rather than
relying solely on polling.  SSF events should be delivered
within seconds of revocation.

(c) Support the emergency kill switch endpoint for immediate
revocation in critical situations.  See Section 12.10 for
security requirements.

(d) Implement cache invalidation for AIP-Static when revocation
occurs.  The ETag mechanism with conditional requests is
RECOMMENDED.  Consumers MUST invalidate cached AIP data upon
receiving revocation events.

(e) Distribute revocation information to all dependent systems
(resource servers, authorization servers, MCP servers) within
a configured SLA (e.g., 60 seconds for high-risk agents).

(f) Implement grace periods for in-flight operations.  Operations
that started before revocation MAY be allowed to complete,
but new operations MUST be rejected.

### 12.8.  Cross-Domain Information Leakage

AIP projection (Section 9) is designed to minimize information
leakage.  Implementations MUST:

(a) Reject projection requests that do not meet the trust policy
for the requested projection level.

(b) Validate the `requester_trust_evidence` JWS before processing
projection requests.

(c) Log all projection requests for audit purposes, including:
-  Requester domain
-  Requested fields
-  Level granted
-  Timestamp

(d) Implement rate limiting on projection endpoints to prevent
enumeration attacks.  See Section 12.11 for guidance.

(e) Sanitize projection responses to remove any fields that
shouldn't be disclosed at the granted level.  Implementations
SHOULD use explicit allowlists rather than denylists.

(f) Implement data minimization principles: only return the
minimum information needed to fulfill the request.

### 12.9.  Trust Anchor Compromise

If the Identity Server's signing key is compromised, all AIP
documents signed with that key become untrustworthy.  Implementations
MUST:

(a) Implement key rotation mechanisms.  The JWKS endpoint MUST
support multiple signing keys with key IDs.

(b) When a key is compromised:
-  Immediately revoke the compromised key in JWKS
-  Publish a revocation event via SSF indicating the compromised
key ID
-  Re-sign all affected AIP documents with a new key
-  Increment the `profile_version` if the compromise requires
protocol changes

(c) Consumers MUST check the revocation event stream and reject
AIP documents signed with revoked keys.

(d) Implement a key compromise recovery procedure:
-  Identify all AIP documents signed with the compromised key
-  Verify that re-signing with the new key doesn't introduce
inconsistencies
-  Notify all dependent systems of the re-signing operation

(e) Consider implementing key rotation on a regular schedule (e.g.,
every 90 days) to limit the window of impact from a compromise.

(f) Implement hardware security modules (HSMs) or similar
secure key storage for protecting private keys.

### 12.10.  Emergency Endpoint Security

The emergency kill switch endpoint
(`credential_lifecycle.revocation.emergency_kill_switch`) requires
special security measures due to its critical nature:

Authentication Requirements:

The emergency kill switch MUST:

(a) Require multi-factor authentication (MFA) for all requests.

(b) Support role-based access control with explicit emergency revocation
permission.

(c) Implement rate limiting with stricter limits than regular
endpoints (e.g., 1 request per minute per authenticated user).

(d) Log all emergency revocation attempts with full audit trail:
-  User identity
-  Timestamp
-  IP address
-  Requested agents for revocation
-  Success/failure status
-  Reason for revocation

(e) Implement approval workflows where required by organizational
policy.  Some deployments may require secondary approval for
emergency revocation.

(f) Require explicit confirmation (e.g., re-typing a reason or
a dangerous command) before executing revocation.

(g) Support "dry run" mode for testing emergency procedures
without actually revoking credentials.

Transport Security:

(a) The endpoint MUST be accessible only via HTTPS with TLS 1.3
or higher.

(b) Implement certificate pinning for high-security deployments.

(c) Consider using mutual TLS (mTLS) for additional security.

(d) Implement IP allowlisting where applicable (e.g., only allow
emergency revocation from corporate network).

Notification:

(a) Upon successful emergency revocation, immediately send
SSF events to all subscribed systems.

(b) Send email or other notifications to:
-  Owner of the affected agent
-  Sponsor of the affected agent
-  Security team

(c) Page on-call security personnel for emergency revocations
of high-risk agents.

Error Handling:

(a) Return generic error messages to prevent information leakage.

(b) Implement exponential backoff for failed attempts to prevent
lockout during actual emergencies.

(c) Provide a status endpoint (separate from the kill switch)
that allows authorized users to check system health.

### 12.11.  Rate Limiting

To prevent denial-of-service attacks and brute-force attempts,
all AIP protocol endpoints MUST implement rate limiting.

Rate Limiting Strategy:

(a) Per-Client Rate Limiting:  Limit requests based on client
identity (e.g., API key, authenticated user).

(b) Per-Agent Rate Limiting:  Limit requests for a specific
`agent_id` to prevent targeted enumeration.

(c) Per-Domain Rate Limiting:  Limit requests from a specific
trust domain for cross federation scenarios.

Implementation Recommendations:

(a) Use token bucket or leaky bucket algorithms for rate limiting.

(b) Return HTTP 429 (Too Many Requests) when limits are exceeded.

(c) Include a `Retry-After` header indicating when the client may
retry.

(d) Log rate limit violations for security monitoring.

(e) Allow rate limit configuration per endpoint type:
-  AIP-Static fetch:  Higher limits (e.g., 1000 req/min)
-  AIP-Dynamic poll:  Higher limits (e.g., 1000 req/min)
-  Projection request:  Lower limits (e.g., 100 req/min)
-  Emergency kill switch:  Strict limits (e.g., 5 req/min)

(f) Implement burst allowance to handle legitimate spikes in traffic.

(g) Consider implementing adaptive rate limiting that adjusts based
on system load and threat level.

(h) For well-known configuration endpoints, use higher limits
(e.g., 10,000 req/min) as these are frequently accessed.

### 12.12.  Semantic Drift Model Security

The semantic drift detection mechanism introduces additional
security considerations:

(a) Model Supply Chain:  The embedding model used for drift
detection is a potential attack vector.  Implementations MUST:
-  Source models from trusted vendors
-  Verify model integrity using cryptographic hashes
-  Consider using air-gapped models for high-security
deployments
-  Pin model versions in AIP documents

(b) Adversarial Prompts:  Sophisticated attackers MAY craft prompts
that maintain high semantic similarity while altering behavior.
Mitigations:
-  Combine semantic drift with other integrity checks
-  Implement behavioral anomaly detection
-  Use conservative drift thresholds for high-risk agents
-  Require human review for drift alerts on critical operations

(c) Model Versioning:  When the embedding model is updated:
-  Semantic similarity scores may change
-  Baseline embeddings must be recomputed
-  Implement version-aware drift detection
-  Store model version with baseline embeddings

(d) False Positives:  Semantic drift detection is not perfect.
Implementations MUST:
-  Treat drift alerts as signals, not definitive proof
-  Require human verification for high-severity alerts
-  Implement feedback loops for threshold tuning
-  Log all drift alerts for analysis

(e) Computational Load:  Embedding computation can be resource-intensive.
Implementations SHOULD:
-  Cache embeddings for frequently-used prompts
-  Use efficient embedding models
-  Implement batching for drift checks
-  Consider offloading to dedicated services

(f) Privacy:  Sending prompts to external embedding services may
expose sensitive data.  Implementations MUST:
-  Use local embedding models for sensitive prompts
-  Sanitize prompts before external processing
-  Ensure data processing agreements with external services
-  Consider using differential privacy techniques

## 13.  Privacy Considerations

### 13.1.  Identifier-Based Tracking

The `agent_id` field is a stable identifier that persists across
the agent's entire lifecycle.  This creates privacy concerns:

(a) Cross-Domain Tracking:  The same `agent_id` may be used across
multiple trust domains, enabling cross-domain correlation of
agent activities.

(b) Persistent Tracking:  The stability of `agent_id` means that
long-term activity patterns can be tracked.

(c) Identifier Disclosure:  The `agent_id` may contain organizational
information (e.g., domain name) that reveals the agent's origin.

Mitigations:

(a) Pairwise Identifiers:  For cross-domain scenarios, implementations
MAY use pairwise identifiers that are unique to each pair of
trust domains.  This prevents correlation across domains.

(b) Identifier Rotation:  Implementations MAY support periodic
identifier rotation for privacy-sensitive agents, though this
has implications for audit trails and long-term trust assessment.

(c) Minimal Disclosure:  In AIP projections (Section 9), the
`agent_id` MAY be partially redacted in Minimal projection level.

(d) Identifier Design:  When designing `agent_id` schemes, avoid
embedding personally identifiable information or sensitive
organizational details.

(e) Consent Framework:  Implementations SHOULD provide a framework
for obtaining consent for cross-domain identifier use.

### 13.2.  Data Minimization

AIP documents contain potentially sensitive information.  The
principle of data minimization requires that implementations:

(a) Collect Only Necessary Data:  Only include fields in AIP
documents that are necessary for the agent's operation and
governance.

(b) Use Projections:  When sharing AIP documents across domains,
use the projection mechanism (Section 9) to limit disclosure
to only necessary fields.

(c) Implement Field-Level Access Control:  Within an organization,
implement access controls on who can view which fields of an
AIP document.

(d) Anonymize Audit Logs:  Audit logs should use pseudonymous
identifiers where possible, with a separate mapping for
authorized investigators.

(e) Data Retention Policies:  Implement clear data retention
policies for AIP documents, with automatic deletion or
archival after decommissioning.

### 13.3.  Cross-Domain Correlation

When AIP documents are shared across trust domains, correlation
risks increase:

(a) Behavioral Profiling:  An agent's behavior patterns across
multiple domains could be correlated to build comprehensive
profiles.

(b) Capability Leakage:  An agent's capabilities in one domain
may reveal information about its role or capabilities in other
domains.

(c) Organization Fingerprinting:  The combination of governance
policies, compliance requirements, and capability sets may
reveal organizational characteristics.

Mitigations:

(a) Projection Levels:  Use the minimal appropriate projection
level for each cross-domain interaction.

(b) Domain Isolation:  Implement logical separation of AIP
documents per domain, with controlled sharing mechanisms.

(c) Correlation Detection:  Implement monitoring for suspicious
cross-domain correlation attempts.

(d) Privacy by Design:  Design AIP documents with cross-domain
privacy in mind, avoiding inclusion of sensitive organizational
details in standard fields.

### 13.4.  Audit Log Privacy

AIP requires comprehensive audit logging, which creates privacy
concerns:

(a) Sensitive Operations:  Audit logs may record sensitive operations
and data access patterns.

(b) Personal Information:  Audit logs may contain personally
identifiable information in operation descriptions.

(c) Long-Term Storage:  Audit logs must be retained for long
periods for compliance, creating privacy risks.

Mitigations:

(a) Audit Log Access Control:  Implement strict access controls
on audit logs, with role-based permissions and audit trails
for access itself.

(b) Log Minimization:  Log only the minimum information necessary
for auditing purposes.  Avoid logging sensitive data in
cleartext.

(c) Log Encryption:  Encrypt audit logs at rest and in transit.

(d) Log Anonymization:  Use pseudonymous identifiers in logs where
possible, with a secure mapping to actual identities.

(e) Log Retention Policies:  Implement documented retention policies
with automatic deletion after the retention period.

(f) Consent and Notification:  Inform users about what audit data
is collected and how it is used.

### 13.5.  Owner Identity Protection

The `owner_binding.owner_id` field identifies the human or
organization responsible for the agent.  This creates privacy
concerns:

(a) Personal Information:  The `owner_id` may contain personally
identifiable information.

(b) Organizational Exposure:  The `owner_id` may reveal organizational
structure and relationships.

(c) Liability Exposure:  The owner may be concerned about liability
exposure for agent actions.

Mitigations:

(a) Projection Controls:  The `owner_binding.owner_id` is NOT
included in Minimal or Standard projections, only in Full
projection.

(b) Pseudonymous Identifiers:  Use pseudonymous identifiers for
owners where possible, with a secure mapping for authorized
access.

(c) Consent Framework:  Implement consent mechanisms for owner
identity disclosure in cross-domain scenarios.

(d) Liability Limitations:  Clearly document in policies the scope
of owner liability for agent actions.

(e) Anonymization Options:  Provide options for anonymous agent
operation where appropriate (e.g., for testing or research).

## 14.  IANA Considerations

### 14.1.  AIP Media Type Registration

This specification requests registration of the following media
type:

Media Type:  application/aip+json
Suffix:  +json
Required parameters:  None
Optional parameters:  None
Encoding considerations:  8-bit; UTF-8 encoding
Security considerations:  See Section 12
Interoperability considerations:  AIP documents are used for agent
identity metadata exchange.  Implementations MUST support the
schema defined in Section 4.
Published specification:  This document
Applications that use this media type:  AI agent systems,
authorization servers, resource servers
Fragment identifier considerations:  Same as for application/json
Additional information:
Magic number(s):  None
File extension(s):  .aip.json
Macintosh file type code(s):  TEXT
Person & email address to contact for further information:
[TBD - Working Group Chair]
Intended usage:  COMMON
Restrictions on usage:  None
Author:  [TBD - Working Group]
Change Controller:  IETF

### 14.2.  AIP Well-Known URI Registration

This specification requests registration of the following well-known
URI:

Well-known URI suffix:  aip-configuration
Specification document(s):  This document, Section 7.2
Person & email address to contact for further information:
[TBD - Working Group Chair]

### 14.3.  AIP Field Registry

This specification establishes a registry for AIP field names.
The registry policy is "Expert Review" as defined in [RFC 8126].

The registry will include:

-  Field name
-  Field path (e.g., "agent_type", "capabilities.declared[*].risk_level")
-  Data type
-  Cardinality (REQUIRED/OPTIONAL/RECOMMENDED)
-  Standard reference (if anchored to another spec)
-  Version introduced
-  Deprecated fields (if any)

### 14.4.  Agent Type Registry

This specification establishes a registry for `agent_type` values.
The registry policy is "Expert Review" as defined in [RFC 8126].

Initial registered values:

| agent_type       | Description                          | Reference |
|------------------|--------------------------------------|-----------|
| assistant        | General-purpose assistant agent       | This spec |
| retrieval        | Information retrieval specialist     | This spec |
| coding           | Code generation and analysis agent   | This spec |
| domain_specific  | Specialized domain agent             | This spec |
| autonomous       | High-autonomy agent                  | This spec |
| supervised       | Requires human supervision           | This spec |

Custom types MUST use the format `<vendor>:<type>`.

### 14.5.  AIP Extension Namespace Registry

This specification establishes a registry for AIP extension
namespace identifiers.  The registry policy is "Expert Review" as
defined in [RFC 8126].

The registry will include:

-  Namespace identifier
-  Maintainer contact information
-  Extension specification reference
-  Version introduced
-  Status (active/deprecated)

Reserved namespace prefixes:
-  "x-":  Reserved for experimental use (MUST NOT be used in production)
-  "ietf-":  Reserved for IETF standard extensions
-  "acme-":  Examples (MUST NOT be used in production)

## 15.  Conformance Requirements

### 15.1.  AIP-Issuer Conformance

An AIP-Issuer is an Identity Server that creates, signs, and manages
AIP documents.  To be conformant as an AIP-Issuer, an implementation:

MUST:
1.  Generate AIP documents conforming to the JSON schema defined in
    Section 4.
2.  Sign AIP-Static documents using JWS [RFC 7515] with algorithms
    RS256 or stronger.
3.  Include all REQUIRED fields as specified in Section 4.
4.  Implement the AIP Discovery and Resolution Protocol as defined in
    Section 7.
5.  Expose a well-known configuration endpoint at
    `/.well-known/aip-configuration`.
6.  Expose a JWKS endpoint for signature verification.
7.  Implement the lifecycle state machine as defined in Section 6.
8.  Implement the trust level model as defined in Section 4.12.
9.  Generate unique nonces for each document version.
10. Support TLS 1.2 or higher for all endpoints.
11. Implement rate limiting on all endpoints.
12. Support AIP document partitioning (AIP-Static and AIP-Dynamic).
13. Support AIP-Dynamic event streaming via OpenID SSF.

SHOULD:
1.  Implement the well-known endpoint versioning strategy.
2.  Support cross-domain resolution via WebFinger.
3.  Implement the projection negotiation protocol.
4.  Support multiple signing keys with key rotation.
5.  Implement certificate pinning guidance for consumers.
6.  Provide monitoring and alerting for security events.
7.  Implement the emergency kill switch with MFA requirements.

MAY:
1.  Support additional signature algorithms beyond RS256 and ES256.
2.  Implement custom projection policies beyond the reference levels.
3.  Support additional event types in AIP-Dynamic beyond the standard set.
4.  Implement advanced behavioral anomaly detection.

### 15.2.  AIP-Consumer Conformance

An AIP-Consumer is a Resource Server, Authorization Server, or
other system that retrieves and uses AIP documents.  To be
conformant as an AIP-Consumer, an implementation:

MUST:
1.  Validate AIP document signatures using JWS [RFC 7515].
2.  Verify the signing key via the JWKS endpoint.
3.  Validate that all REQUIRED fields are present.
4.  Check the `document_metadata.expires_at` and reject expired documents.
5.  Validate nonces to prevent replay attacks.
6.  Use TLS 1.2 or higher for all AIP protocol communication.
7.  Implement rate limiting when communicating with AIP endpoints.
8.  Validate the `lifecycle_state` and reject operations from non-active
    agents unless policy allows otherwise.
9.  Respect the `trust_level` when making authorization decisions.
10. Validate delegation chains according to Section 8.4.

SHOULD:
1.  Cache AIP-Static documents with ETag-based invalidation.
2.  Subscribe to AIP-Dynamic event streams for real-time updates.
3.  Implement fallback polling for event stream failures.
4.  Validate attestation evidence before granting access.
5.  Check integrity verification status for high-risk operations.
6.  Log all AIP validation failures for security monitoring.

MAY:
1.  Implement custom trust level evaluation policies.
2.  Use pairwise identifiers for privacy-sensitive scenarios.
3.  Implement advanced behavioral monitoring.
4.  Support multiple AIP document versions with migration logic.

### 15.3.  AIP-Projector Conformance

An AIP-Projector is an Identity Server that implements the AIP
Projection mechanism for cross-domain sharing.  To be conformant as an
AIP-Projector, an implementation:

MUST:
1.  Implement the projection negotiation protocol (Section 9.2).
2.  Validate `requester_trust_evidence` JWS before processing requests.
3.  Support the three standard projection levels (Minimal, Standard, Full).
4.  Enforce field visibility rules as specified in Section 9.3.
5.  Return HTTP 403 for requests that exceed the granted trust level.
6.  Implement rate limiting on projection endpoints.
7.  Log all projection requests for audit purposes.

SHOULD:
1.  Implement custom projection policies beyond the reference levels.
2.  Support projection negotiation with field-level granularity.
3.  Implement projection caching with appropriate TTLs.
4.  Provide monitoring for projection request patterns.

MAY:
1.  Support additional projection levels beyond the standard three.
2.  Implement automated projection level negotiation.
3.  Support projection templates for common scenarios.

### 15.4.  Version Negotiation

AIP-Issuers and AIP-Consumers MUST implement version negotiation:

(a) Version Declaration:  The `profile_version` field MUST be included
in all AIP documents.

(b) Version Advertisement:  The well-known configuration endpoint
MUST include an `aip_version_supported` array.

(c) Version Compatibility:  Consumers MUST:
1. Check `aip_version_supported` before using AIP documents
2. Reject documents with incompatible MAJOR versions
3. Gracefully handle documents with compatible MINOR versions
4. Document supported versions in implementation metadata

(d) Migration Strategy:  Issuers MUST provide a migration path when
introducing breaking changes:
1. Support old and new versions simultaneously
2. Provide migration tools and documentation
3. Communicate deprecation timelines
4. Offer fallback mechanisms for non-upgraded consumers

## 16.  References

### 16.1.  Normative References

[ISO.8601.2004]
International Organization for Standardization, "Data elements
and interchange formats — Information interchange —
Representation of dates and times", ISO 8601:2004, 2004.

[OIDC-A]
[TBD - OpenID Connect for Agents specification]

[OIDC-Core]
Sakimura, N., Bradley, J., Jones, M., Meder, E., and
C. de Medeiros, "OpenID Connect Core 1.0 incorporating errata
set 1", November 2014.  Available at
https://openid.net/specs/openid-connect-core-1_0.html

[OIDC-SSF]
Lodderstedt, T., Bradley, J., Labunets, A., and
S. Cokus, "OpenID Shared Signals Framework",
Available at https://openid.net/specs/openid-ssf-1_0.html

[RFC7515]
Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature
(JWS)", RFC 7515, DOI 10.17487/RFC7515, May 2015.

[RFC7517]
Jones, M., "JSON Web Key (JWK)", RFC 7517,
DOI 10.17487/RFC7517, May 2015.

[RFC2119]
Bradner, S., "Key words for use in RFCs to Indicate
Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC2818]
Rescorla, E., "HTTP Over TLS", RFC 2818, May 2000.

[RFC3986]
Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
Resource Identifier (URI): Generic Syntax", STD 66,
RFC 3986, January 2005.

[RFC4122]
Leach, P., Mealling, M., and R. Salz, "A Universally Unique
IDentifier (UUID) URN Namespace", RFC 4122, July 2005.

[RFC7033]
Jones, P., Salmon, S., and J. Bradley, "WebFinger",
RFC 7033, September 2013.

[RFC7232]
Fielding, R., Ed. and J. Reschke, Ed., "Hypertext Transfer
Protocol (HTTP/1.1): Conditional Requests", RFC 7232,
June 2014.

[RFC7519]
Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token
(JWT)", RFC 7519, May 2015.

[RFC8174]
Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119
Key Words", BCP 14, RFC 8174, May 2017.

[RFC8126]
Cotton, M., Leiba, B., and T. Narten, "Guidelines for
Writing an IANA Considerations Section in RFCs", BCP 26,
RFC 8126, June 2017.

[RFC8414]
Jones, M., Sakimura, N., and J. Bradley, "OAuth 2.0
Authorization Server Metadata", RFC 8414, June 2018.

[RFC8693]
Lodderstedt, T., Ed., "OAuth 2.0 Token Exchange", RFC 8693,
February 2020.

[SPIFFE]
The SPIFFE Community, "SPIFFE Trust Domain and Bundle", 2019.

[I-D.ietf-wimse-arch]
[TBD - WIMSE Architecture]

[I-D.ietf-wimse-workload-creds]
[TBD - WIMSE Workload Credentials]

[I-D.ietf-wimse-wpt]
[TBD - WIMSE Workload Proof Token]

[I-D.ni-wimse-ai-agent-identity]
Ni, L., et al., "Workload Identity and Management for AI
Agents", draft-ni-wimse-ai-agent-identity, 2026.

[I-D.liu-agent-operation-authorization]
Liu, Y., et al., "Agent Operation Authorization", draft-liu-agent-
operation-authorization, 2026.

[I-D.klrc-aiagent-auth]
Kasselman, C., et al., "AI Agent Authentication and
Authorization", draft-klrc-aiagent-auth-00, 2026.

[I-D.ietf-rats-eat]
Tsukamoto, K., et al., "Entity Attestation Token (EAT)",
draft-ietf-rats-eat, 2023.

### 16.2.  Informative References

[MCP]
[TBD - Model Context Protocol specification]

[A2A]
[TBD - Agent-to-Agent Protocol specification]

[NIST-AI-Agent]
NIST, "Accelerating the Adoption of Software and AI Agent
Identity and Authorization", 2025.

[Agentic-JWT]
[TBD - Agentic JWT academic paper]

## Appendix A.  Complete AIP Document Example

This appendix provides a complete example of an AIP document with
all fields populated.

```json
{
  "profile_version": "1.0",
  "document_metadata": {
    "issuer": "wimse://trust.example.com",
    "issued_at": "2026-03-07T10:00:00Z",
    "expires_at": "2026-03-08T10:00:00Z",
    "created_at": "2026-03-01T08:00:00Z",
    "updated_at": "2026-03-07T10:00:00Z",
    "document_id": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "nonce": "n-0S6_WzA2Mj"
  },
  "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
  "agent_type": "coding",
  "display_name": "Enterprise Coding Assistant",
  "agent_model": "gpt-4",
  "agent_version": "2026.03",
  "agent_provider": "openai.com",
  "agent_instance_id": "instance-abc-123",
  "framework": {
    "name": "EnterpriseClaw",
    "version": "2.0.0",
    "runtime": "node:20-alpine",
    "protocol_support": ["MCP/1.0", "A2A/0.3"],
    "attestation_formats_supported": ["EAT"],
    "delegation_methods_supported": ["jwt"]
  },
  "owner_binding": {
    "owner_type": "user",
    "owner_id": "developer@example.com",
    "binding_model": "owner_mediated",
    "binding_proof": {
      "proof_type": "dual_identity_credential",
      "owner_public_key_thumbprint": "SHA-256:a1b2c3d4e5f6...",
      "binding_timestamp": "2026-03-07T10:00:00Z",
      "attestation_method": "hardware_key"
    },
    "delegation_authority": {
      "can_delegate": true,
      "max_delegation_depth": 2,
      "delegation_scope_ceiling": ["code.read", "code.execute"],
      "delegation_purpose": "Delegated coding tasks",
      "delegation_constraints": {
        "max_duration": 3600,
        "allowed_resources": ["/workspace/**"]
      }
    },
    "delegation_chain": [
      {
        "iss": "https://auth.example.com",
        "sub": "user_12345",
        "aud": "agent-instance-abc-123",
        "delegated_at": "2026-03-07T10:00:00Z",
        "scope": "code.execute file.read",
        "purpose": "Code assistance",
        "constraints": {
          "max_duration": 7200,
          "allowed_resources": ["/workspace/**"]
        },
        "jti": "urn:uuid:step-unique-id-123"
      }
    ]
  },
  "capabilities": {
    "declared": [
      {
        "capability": "code.read",
        "scope": "/workspace/**",
        "risk_level": "low",
        "mcp_tool_ref": "filesystem/readFile"
      },
      {
        "capability": "code.execute",
        "scope": "/workspace/**",
        "risk_level": "medium",
        "mcp_tool_ref": "code-runner/execute"
      },
      {
        "capability": "file.write",
        "scope": "/workspace/**/*.py",
        "risk_level": "medium"
      }
    ],
    "restricted": [
      {
        "capability": "credentials.access",
        "restriction_reason": "platform_default",
        "override_requires": "never"
      },
      {
        "capability": "system.admin",
        "restriction_reason": "owner_policy",
        "override_requires": "sponsor_approval"
      }
    ],
    "autonomy_level": "human_on_the_loop"
  },
  "attestation": {
    "format": "urn:ietf:params:oauth:token-type:eat",
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVhdCtqd3QifQ...",
    "timestamp": "2026-03-07T10:00:00Z",
    "verification_endpoint": "https://auth.example.com/agent/attestation",
    "evidence_type": "eat_profile",
    "evidence_ref": "urn:ietf:params:eat:ai-agent:v1",
    "attestation_results": {
      "platform": {
        "type": "container",
        "orchestrator": "kubernetes",
        "namespace": "agent-workloads",
        "verified": true
      },
      "software": {
        "binary_hash": "SHA-256:e5f6a7b8c9d0...",
        "config_hash": "SHA-256:c3d4e5f6a7b8...",
        "supply_chain_verified": true
      },
      "hardware": {
        "tpm_present": false,
        "secure_enclave": false,
        "key_protection": "software"
      }
    },
    "last_attestation_time": "2026-03-07T10:00:00Z",
    "next_attestation_deadline": "2026-03-07T11:00:00Z"
  },
  "integrity": {
    "core_invariants": {
      "system_config_hash": "SHA-256:b2c3d4e5f6a7...",
      "security_policy_hash": "SHA-256:e5f6a7b8c9d0..."
    },
    "controlled_mutables": {
      "tools_config": {
        "mutation_policy": "append_only",
        "allowed_sources": ["registry.internal.example.com"],
        "change_audit_required": true
      },
      "prompt_template": {
        "mutation_policy": "version_tracked",
        "max_drift_from_baseline": 0.3,
        "change_audit_required": true
      }
    },
    "composite_hash": "SHA-256:d4e5f6a7b8c9...",
    "verification_endpoint": "https://auth.example.com/agents/verify-integrity",
    "last_verified": "2026-03-07T10:00:00Z"
  },
  "governance": {
    "sponsor": {
      "type": "user",
      "id": "platform-admin@example.com",
      "responsibility": "lifecycle_owner",
      "contact_channel": {
        "type": "email",
        "address": "platform-admin@example.com"
      }
    },
    "lifecycle_policy": {
      "max_idle_duration": "PT72H",
      "auto_deactivation": true,
      "credential_rotation_interval": "PT1H",
      "mandatory_review_interval": "P7D",
      "decommission_procedure": "https://docs.internal.example.com/agent-lifecycle/decommission"
    },
    "compliance_requirements": ["SOC2"],
    "risk_classification": "medium"
  },
  "credential_lifecycle": {
    "primary_credential": {
      "type": "WIT",
      "issuer": "wimse://trust.example.com",
      "current_credential_id": "urn:uuid:credential-wit-001",
      "issued_at": "2026-03-07T10:00:00Z",
      "expires_at": "2026-03-07T11:00:00Z",
      "rotation_status": "active"
    },
    "binding_credential": {
      "type": "dual_identity_credential",
      "binding_model": "owner_mediated",
      "issued_at": "2026-03-07T09:55:00Z",
      "expires_at": "2026-03-08T09:55:00Z"
    },
    "secondary_credentials": [
      {
        "type": "oauth2_token",
        "target_system": "github.com",
        "exchange_mechanism": "token_exchange",
        "scope": "repo:read",
        "expires_at": "2026-03-07T10:30:00Z"
      }
    ],
    "revocation": {
      "revocation_endpoint": "https://auth.example.com/agents/revoke",
      "revocation_check_interval": "PT5M",
      "emergency_kill_switch": "https://auth.example.com/agents/emergency-stop",
      "ssf_stream_id": "stream-agent-events-001"
    }
  },
  "observability": {
    "audit_log_endpoint": "https://audit.example.com/agent-events",
    "event_types": [
      "credential_issued",
      "authorization_granted",
      "authorization_denied",
      "policy_violation",
      "delegation_created",
      "integrity_failure"
    ],
    "ssf_config": {
      "caep_stream_id": "stream-agent-caep-events-001",
      "risc_stream_id": "stream-agent-risc-events-001"
    },
    "correlation_id_scheme": "urn:uuid",
    "behavior_monitoring": {
      "enabled": true,
      "baseline_model_ref": "model-baseline-v1.2",
      "anomaly_threshold": 0.85,
      "alert_endpoints": ["https://alerting.example.com/webhooks/agent-alerts"]
    },
    "discovery_endpoints": {
      "agent_attestation_endpoint": "https://auth.example.com/agent/attestation",
      "agent_capabilities_endpoint": "https://auth.example.com/.well-known/agent-capabilities"
    }
  },
  "trust_level": "verified",
  "lifecycle_state": "active",
  "document_partitioning": {
    "static_ref": "https://registry.example.com/agents/550e8400...",
    "static_etag": "W/\"v1.3\"",
    "dynamic_ssf_stream": "https://ssf.example.com/streams/stream-agent-events-001",
    "dynamic_polling_fallback": "https://registry.example.com/agents/550e8400.../dynamic",
    "cache_policy": {
      "static_max_age_seconds": 3600,
      "dynamic_delivery": "push_preferred"
    }
  },
  "extensions": {
    "acme": {
      "department": "engineering",
      "cost_center": "ENG-001"
    }
  }
}
```

## Appendix B.  AIP-to-draft-liu Mapping Table

This appendix provides the complete mapping between AIP fields and
draft-liu `agent_identity` claim fields.

| AIP Field Path                                    | draft-liu Field            | Mapping Method |
|---------------------------------------------------|----------------------------|----------------|
| profile_version                                   | version                    | Direct         |
| agent_id (UUID portion)                           | id                         | Extract UUID   |
| owner_binding.owner_id                            | issuedTo                   | Direct         |
| agent_id (trust domain portion)                   | issuer                     | Extract domain |
| credential_lifecycle.primary_credential.issued_at | issuanceDate             | Direct         |
| credential_lifecycle.primary_credential.issued_at | validFrom                | Direct         |
| credential_lifecycle.primary_credential.expires_at| expires                  | Direct         |
| framework.name + agent_type                       | issuedFor.client           | Concatenate    |
| attestation.attestation_results.platform.namespace| issuedFor.clientInstance| Direct         |
| document_metadata.issuer                          | (issuer extension)        | Extension      |
| document_partitioning.static_ref                  | (aip_ref extension)        | Extension      |

## Appendix C.  AIP-to-OIDC-A Mapping Table

This appendix provides the mapping between AIP fields and
OIDC-A standard claims.

| AIP Field Path                                    | OIDC-A Claim               |
|---------------------------------------------------|----------------------------|
| agent_type                                        | agent_type                 |
| agent_model                                       | agent_model                |
| agent_provider                                    | agent_provider             |
| agent_instance_id                                 | agent_instance_id          |
| owner_binding.delegation_chain                    | delegation_chain           |
| capabilities.oidc_a_format                        | agent_capabilities         |
| attestation.format                                | agent_attestation.format   |
| attestation.token                                 | agent_attestation.token    |
| attestation.timestamp                             | agent_attestation.time     |
| attestation.verification_endpoint                 | agent_attestation.endpoint |
| framework.attestation_formats_supported           | attestation_formats_supported|
| framework.delegation_methods_supported           | delegation_methods_supported|
| framework.models_supported                        | agent_models_supported     |
| document_metadata.issuer                          | (issuer claim)             |
| document_metadata.expires_at                      | (exp claim)                |

## Appendix D.  Compliance Mapping (NIST)

This appendix maps AIP fields to NIST AI Agent Standards Initiative
requirements.

| NIST Requirement                          | AIP Field(s)                              | Compliance Mechanism |
|-------------------------------------------|-------------------------------------------|----------------------|
| Unique Agent Identification               | agent_id                                  | WIMSE URI format     |
| Lifecycle Management                      | lifecycle_state, governance.lifecycle_policy | State machine        |
| Owner Responsibility                      | governance.sponsor                         | Sponsor designation  |
| Audit Trail                               | observability.audit_log_endpoint          | Event logging        |
| Attestation                               | attestation                               | EAT verification     |
| Minimal Privilege                         | capabilities.declared, scope narrowing    | Capability limits    |
| Revocation                                | credential_lifecycle.revocation           | Immediate revocation |
| Behavioral Monitoring                     | observability.behavior_monitoring         | Anomaly detection    |
| Trust Assessment                          | trust_level                               | Qualitative levels   |
| Security Event Response                   | lifecycle_state transitions, emergency kill switch | State changes |

## Appendix E.  JSON Schema (Informative)

This appendix provides an informative JSON Schema for AIP document
validation.  Implementers MAY use this schema for validation but
MUST refer to the normative text in Section 4 for authoritative
specification.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/schemas/aip-v1.0.json",
  "title": "Agent Identity Profile",
  "description": "AI Agent Identity Profile specification v1.0",
  "type": "object",
  "required": [
    "profile_version",
    "document_metadata",
    "agent_id",
    "agent_type",
    "display_name",
    "agent_model",
    "agent_provider",
    "agent_instance_id",
    "framework",
    "owner_binding",
    "capabilities",
    "attestation",
    "integrity",
    "governance",
    "credential_lifecycle",
    "observability",
    "trust_level",
    "lifecycle_state"
  ],
  "properties": {
    "profile_version": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+$"
    },
    "document_metadata": {
      "type": "object",
      "required": ["issuer", "issued_at", "expires_at", "created_at", "updated_at", "document_id", "nonce"],
      "properties": {
        "issuer": {"type": "string"},
        "issued_at": {"type": "string", "format": "date-time"},
        "expires_at": {"type": "string", "format": "date-time"},
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "document_id": {"type": "string", "format": "uri"},
        "nonce": {"type": "string", "minLength": 16}
      }
    },
    "agent_id": {
      "type": "string",
      "format": "uri"
    },
    "agent_type": {
      "type": "string",
      "enum": ["assistant", "retrieval", "coding", "domain_specific", "autonomous", "supervised"]
    },
    "display_name": {"type": "string", "maxLength": 256},
    "agent_model": {"type": "string"},
    "agent_version": {"type": "string"},
    "agent_provider": {"type": "string"},
    "agent_instance_id": {"type": "string"},
    "framework": {
      "type": "object",
      "required": ["name", "version"],
      "properties": {
        "name": {"type": "string"},
        "version": {"type": "string"},
        "runtime": {"type": "string"},
        "protocol_support": {"type": "array", "items": {"type": "string"}},
        "attestation_formats_supported": {"type": "array", "items": {"type": "string"}},
        "delegation_methods_supported": {"type": "array", "items": {"type": "string"}}
      }
    },
    "owner_binding": {
      "type": "object",
      "required": ["owner_type", "owner_id", "binding_model", "delegation_authority", "delegation_chain"],
      "properties": {
        "owner_type": {"type": "string"},
        "owner_id": {"type": "string"},
        "binding_model": {"type": "string", "enum": ["agent_mediated", "owner_mediated", "server_mediated"]},
        "binding_proof": {"type": "object"},
        "delegation_authority": {"type": "object"},
        "delegation_chain": {"type": "array", "items": {"type": "object"}}
      }
    },
    "capabilities": {
      "type": "object",
      "required": ["declared", "autonomy_level"],
      "properties": {
        "declared": {"type": "array"},
        "restricted": {"type": "array"},
        "autonomy_level": {"type": "string", "enum": ["human_in_the_loop", "human_on_the_loop", "human_out_of_the_loop"]}
      }
    },
    "attestation": {
      "type": "object",
      "required": ["format", "token", "timestamp", "verification_endpoint", "attestation_results", "last_attestation_time", "next_attestation_deadline"],
      "properties": {
        "format": {"type": "string"},
        "token": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "verification_endpoint": {"type": "string", "format": "uri"},
        "attestation_results": {"type": "object"},
        "last_attestation_time": {"type": "string", "format": "date-time"},
        "next_attestation_deadline": {"type": "string", "format": "date-time"}
      }
    },
    "integrity": {
      "type": "object",
      "required": ["core_invariants", "composite_hash", "verification_endpoint"],
      "properties": {
        "core_invariants": {"type": "object"},
        "controlled_mutables": {"type": "object"},
        "composite_hash": {"type": "string"},
        "verification_endpoint": {"type": "string", "format": "uri"},
        "last_verified": {"type": "string", "format": "date-time"}
      }
    },
    "governance": {
      "type": "object",
      "required": ["sponsor", "lifecycle_policy", "risk_classification"],
      "properties": {
        "sponsor": {"type": "object"},
        "lifecycle_policy": {"type": "object"},
        "compliance_requirements": {"type": "array"},
        "risk_classification": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
      }
    },
    "credential_lifecycle": {
      "type": "object",
      "required": ["primary_credential", "revocation"],
      "properties": {
        "primary_credential": {"type": "object"},
        "binding_credential": {"type": "object"},
        "secondary_credentials": {"type": "array"},
        "revocation": {"type": "object"}
      }
    },
    "observability": {
      "type": "object",
      "required": ["audit_log_endpoint", "event_types", "correlation_id_scheme"],
      "properties": {
        "audit_log_endpoint": {"type": "string", "format": "uri"},
        "event_types": {"type": "array"},
        "ssf_config": {"type": "object"},
        "correlation_id_scheme": {"type": "string"},
        "behavior_monitoring": {"type": "object"},
        "discovery_endpoints": {"type": "object"}
      }
    },
    "trust_level": {
      "type": "string",
      "enum": ["unverified", "verified", "trusted", "highly_trusted", "compromised"]
    },
    "lifecycle_state": {
      "type": "string",
      "enum": ["created", "active", "suspended", "revoked", "decommissioned"]
    },
    "document_partitioning": {
      "type": "object",
      "required": ["static_ref", "static_etag", "dynamic_ssf_stream", "cache_policy"],
      "properties": {
        "partition_strategy": {"type": "string"},
        "static_ref": {"type": "string", "format": "uri"},
        "static_etag": {"type": "string"},
        "dynamic_ssf_stream": {"type": "string", "format": "uri"},
        "dynamic_polling_fallback": {"type": "string", "format": "uri"},
        "cache_policy": {"type": "object"}
      }
    },
    "extensions": {
      "type": "object",
      "additionalProperties": true
    }
  }
}
```

---

## Authors' Addresses

[TBD - Working Group Authors]

This document is a product of the IETF Agent Identity Working Group.
