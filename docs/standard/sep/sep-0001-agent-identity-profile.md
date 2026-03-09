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
credential lifecycle state, and observability configuration.

AIP is designed as a complementary layer within the existing protocol
ecosystem.  It bridges the gap between workload-level credential
systems (WIMSE WIT/WPT), user-level authentication protocols
(OpenID Connect, OIDC-A), and operation-level authorization frameworks
(AOAT) by providing a unified, cacheable, and verifiable identity
metadata document that can be referenced throughout an agent's
lifecycle.

This specification defines the AIP data model, the document
partitioning strategy (AIP-Static and AIP-Dynamic), the lifecycle
state machine, the discovery and resolution protocol, the delegation
chain constraints for multi-agent scenarios, the integrity
verification model, and the cross-domain projection mechanism for
federated trust environments.

### Status

This document is a **Specification Enhancement Proposal (SEP)** for the
[Open Agent Auth](https://github.com/alibaba/open-agent-auth) project.
It is currently in **Draft** status and open for community review.

- **Tracking Issue**: [GitHub Issue TBD](https://github.com/alibaba/open-agent-auth/issues/TBD)
- **Discussion**: Comments and feedback are welcome via GitHub Issues and Pull Requests

### Copyright Notice

Copyright (c) 2026 Alibaba Group and the persons identified as the
document authors. Licensed under the Apache License 2.0.

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
    12.1. AIP Document Forgery
    12.2. Delegation Chain Attacks
    12.3. Integrity Bypass
    12.4. Prompt Injection and Intent Deviation
    12.5. Revocation Timeliness
    12.6. Cross-Domain Information Leakage
    12.7. Trust Anchor Compromise
13. IANA Considerations
    13.1. AIP Media Type Registration
    13.2. AIP Well-Known URI Registration
    13.3. AIP Field Registry
    13.4. Agent Type Registry
14. References
    14.1. Normative References
    14.2. Informative References
Appendix A.  Complete AIP Document Example
Appendix B.  AIP-to-draft-liu Mapping Table
Appendix C.  AIP-to-OIDC-A Mapping Table
Appendix D.  Compliance Mapping (NIST)

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

### 1.3.  Scope

This specification defines:

-  The AIP JSON data model and its field semantics.
-  The document partitioning strategy (AIP-Static and AIP-Dynamic).
-  The lifecycle state machine and state transition rules.
-  The discovery and resolution protocol for AIP documents.
-  The delegation chain constraints for multi-agent identity.
-  The cross-domain projection mechanism.
-  The integrity verification model.
-  The integration points with WIMSE, OIDC/OIDC-A, AOAT, MCP, A2A,
   and OpenID SSF.

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
   governance policies, credential lifecycle, and observability
   configuration.

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
  "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
  "agent_type": "coding",
  "display_name": "Enterprise Coding Assistant",
  "agent_model": "gpt-4",
  "agent_provider": "openai.com",
  "agent_instance_id": "instance-abc-123",
  "framework": {"name": "enterprise-coding-assistant", "version": "1.0", "specification": "AIP-01"},
  "owner_binding": {"binding_model": "server_mediated", "owner_id": "urn:entity:org:example-corp"}",
  "capabilities": {"declared": [{"capability": "file.read"}, {"capability": "code.generate"}], "restricted_to": ["internal-network"], "autonomy_level": 3},
  "attestation": {"format": "urn:ietf:params:oauth:token-type:eat", "timestamp": 1714348800, "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6ImVhdCtqd3QifQ...""},
  "integrity": {"core_invariants": ["agent_id", "classification.agent_type"], "controlled_mutables": ["trust_level", "observability.metrics"]},
  "governance": {"policy_compliance": ["iso-27001", "soc-2"], "audit_logs_retention": "7 years", "data_residency": "eu"}",
  "credential_lifecycle": {"primary_credential": {"type": "WIT", "rotation_interval": 3600}, "backup_credentials": [], "recovery_mechanism": "multi-sig"}",
  "observability": {"metrics_endpoint": "/metrics", "logs_endpoint": "/logs", "trace_enabled": true},
  "document_partitioning": {"partition_strategy": "static_dynamic_split", "sync_interval": 300, "delta_compression": true},
  "lifecycle_state": "active"
}
```

The following top-level fields are OPTIONAL:

-  `agent_version`:  The version identifier of the agent model.
-  `extensions`:  A JSON object for domain-specific extensions
   (see Section 13.3).

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
   characters.

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
   key, platform authenticator).  No network communication with
   the Identity Server is REQUIRED at binding time.  Suitable for
   individual developers and local-first deployments.

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
  "delegated_at": 1714348800,
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
    "timestamp": 1714348800,
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
:  The Unix timestamp when the attestation was generated.

verification_endpoint (REQUIRED):
:  The HTTP endpoint where the attestation token can be verified.
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
:  The timestamp of the last successful attestation.

next_attestation_deadline (REQUIRED):
:  The deadline by which a new attestation MUST be provided.
   Failure to attest before this deadline SHALL result in the
   agent being suspended or revoked.

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

   -  revocation_endpoint:  HTTP endpoint for manual revocation.
   -  revocation_check_interval:  Interval at which the agent
      MUST check revocation status.  RECOMMENDED default is PT5M.
   -  emergency_kill_switch:  Emergency revocation endpoint that
      bypasses normal revocation checking and immediately revokes
      all credentials.  RECOMMENDED for agents with
      autonomy_level "human_out_of_the_loop".
   -  ssf_stream_id:  OpenID Shared Signals Framework stream ID
      for receiving revocation events.

### 4.11. Observability (observability)

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
:  HTTP endpoint where audit events are submitted.

event_types (REQUIRED):
:  Array of event types that the agent generates.  Implementations
   MUST support at least the event types listed in the example.

ssf_config (RECOMMENDED):
:  Configuration for OpenID Shared Signals Framework
   [RFC 8414] event subscriptions.  `caep_stream_id` is for
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
-  `document_partitioning.static_ref` (self-reference)
-  `document_partitioning.static_etag` (version identifier)
-  `document_partitioning.dynamic_ssf_stream` (event stream endpoint)

AIP-Static MUST NOT include:

-  `credential_lifecycle.primary_credential.rotation_status`
-  `attestation.last_attestation_time` (static attestation
   configuration is included, but the timestamp is not)
-  Any real-time behavioral monitoring data

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
in real-time.  Each event contains:

```json
{
  "event_type": "credential_rotated",
  "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
  "timestamp": 1714348800,
  "event_id": "evt-12345",
  "data": { ... }
}
```

The `data` object contains the specific state change.  For example,
a `credential_rotated` event might contain:

```json
{
  "event_type": "credential_rotated",
  "agent_id": "wimse://trust.example.com/agents/...",
  "timestamp": 1714348800,
  "event_id": "evt-12345",
  "data": {
    "credential_id": "urn:uuid:credential-abc-123",
    "previous_expires_at": 1714348800,
    "new_expires_at": 1714352400,
    "rotation_status": "active"
  }
}
```

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
    expiration, trust level decrease), implement appropriate
    safeguards (e.g., revoke sessions, require re-authorization).

(d) Implement a fallback polling mechanism if event streaming is
    unavailable.  Polling interval SHOULD be no more than twice
    the `credential_lifecycle.revocation.revocation_check_interval`.

(e) Handle network partitions gracefully: if AIP-Dynamic updates
    cannot be received, the agent SHOULD be treated as having a
    degraded trust level until connectivity is restored.

## 6.  AIP Lifecycle State Machine

### 6.1.  States

An AIP document transitions through the following states during its
lifecycle:

Created:
:  The AIP document has been generated but has not yet received
   any endorsements.  In this state, the agent MUST NOT be used
   for any operations.  This is a transient initialization state.

Active:
:  The AIP document has been fully endorsed and the agent is
   authorized to operate within its declared capabilities.  This
   is the normal operating state.

Suspended:
:  The agent has been temporarily suspended due to a detected
   anomaly, policy violation, or explicit administrative action.
   In this state, ongoing operations are allowed to complete
   gracefully, but new operations MUST be rejected.  The agent
   MAY return to the Active state after the suspension cause is
   resolved.

Revoked:
:  The AIP document has been permanently revoked.  This is an
   irreversible terminal state.  All credentials MUST be
   invalidated immediately.  All ongoing operations SHOULD be
   terminated where possible.

Decommissioned:
:  The agent has been formally decommissioned according to the
   decommissioning procedure documented in
   `governance.lifecycle_policy.decommission_procedure`.  This is
   an irreversible terminal state reached after a planned shutdown
   process.

### 6.2.  State Transitions

The following state transitions are defined:

Created -> Active:
:  Triggered when the AIP document receives at least one valid
   endorsement from a trusted authority.  The endorsement MUST
   cover the `agent_id` and the relevant sections of the AIP
   document (typically `owner_binding` and `integrity`).

Active -> Suspended:
:  Triggered by any of the following conditions:
   (a) Trust score falls below the suspension threshold.
   (b) Integrity verification fails.
   (c) Policy violation detected (e.g., accessing restricted
       capabilities without approval).
   (d) Administrative action (sponsor or security team).
   (e) Failure to complete attestation before
       `attestation.next_attestation_deadline`.

Suspended -> Active:
:  Triggered when the suspension cause is resolved:
   (a) Trust score recovers above the activation threshold.
   (b) Integrity verification succeeds.
   (c) Policy violation is remediated.
   (d) Administrative action (sponsor approval).
   When returning to Active, the trust score SHOULD be reset
   to a conservative baseline (not the pre-suspension level).

Active/Suspended -> Revoked:
:  Triggered by any of the following conditions:
   (a) Explicit revocation by the owner or sponsor.
   (b) Critical security incident (e.g., credential compromise
       detected).
   (c) Failure to attend to suspension within a defined grace period.
   (d) Regulatory or legal requirement.
   This transition MUST be logged with the revocation reason.

Active -> Decommissioned:
:  Triggered by a planned decommissioning process.  The agent
   MUST complete all ongoing operations, release all held resources,
   and generate a final audit log.  The transition to Decommissioned
   MUST be preceded by a transition to Active (to allow graceful
   shutdown) unless emergency circumstances apply.

Revoked -> Decommissioned:
:  MAY be performed after a revocation to formally close the
   agent's lifecycle records.  No additional conditions are REQUIRED.

### 6.3.  Transition Triggers

State transitions are triggered by events from the following sources:

(a) Lifecycle Management API:  Administrative operations through
    the Identity Server's lifecycle management interface.

(b) Trust Engine:  Trust score changes detected by the trust
    evaluation service.

(c) Integrity Monitor:  Integrity verification failures or
    configuration changes.

(d) Attestation Service:  Attestation success or failure events.

(e) Policy Engine:  Policy violation detections.

(f) Emergency Kill Switch:  Activation of the emergency revocation
    endpoint.

(g) Decommissioning Workflow:  Automated or manual decommissioning
    procedure execution.

### 6.4.  Protocol Behavior per State

The behavior of protocols consuming AIP MUST vary based on the
`lifecycle_state`:

Created:
:  Authorization Servers MUST reject all authorization requests.
    Resource Servers MUST reject all access requests.  The AIP
    document SHOULD be treated as non-existent for authorization
    purposes.

Active:
:  Normal operation.  Authorization Servers MAY evaluate requests
    based on the agent's trust level and declared capabilities.
    Resource Servers MAY grant access subject to their authorization
    policies.

Suspended:
:  Authorization Servers MUST suspend ongoing authorization flows
    but MAY allow in-flight operations to complete.  New
    authorization requests MUST be rejected.  Resource Servers
    SHOULD accept requests with valid AOATs issued before the
    suspension timestamp but SHOULD reject new requests.

Revoked:
:  All authorization requests MUST be rejected immediately.
    Resource Servers MUST invalidate any cached permissions.
    The `credential_lifecycle.revocation.emergency_kill_switch`
    endpoint SHOULD be called to propagate revocation to all
    systems.

Decommissioned:
:  Same protocol behavior as Revoked, but with different audit
    semantics (decommissioning rather than security revocation).

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
  "jwks_uri": "https://auth.<trust-domain>/.well-known/jwks.json"
}
```

Field definitions:

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

### 7.3.  AIP Registry API

The AIP Registry API provides endpoints for retrieving AIP
documents.

#### 7.3.1.  Retrieve AIP-Static

```
GET {registry_endpoint}/{url-encoded-agent-id}
```

Headers:
-  Accept: application/aip+json

Response (200 OK):
```json
{
  "aip_static": {
    "profile_version": "1.0",
    "agent_id": "wimse://trust.example.com/agents/550e8400-e29b-41d4-a716-446655440000",
    "agent_type": "coding"
  },
  "signature": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}
```

The `signature` is a JWS [RFC 7515] over the `aip_static` object.

Response codes:
-  200 OK:  AIP-Static document found.
-  404 Not Found:  Agent not found.
-  410 Gone:  Agent was decommissioned.
-  429 Too Many Requests:  Rate limit exceeded.

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
  "last_updated": 1714348800,
  "credential_lifecycle": {"primary_credential": {"type": "WIT"}},
  "attestation": {"format": "urn:ietf:params:oauth:token-type:eat"}},
  "trust_level": "verified",
  "behavioral_anomalies": [ ... ]
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

4.  Client validates the response and extracts the
    `registry_endpoint`.

5.  Client retrieves AIP-Static:
    ```
    GET https://registry.trust.example.com/agents/<agent-id>
    ```

6.  Client validates the JWS signature using the JWKS from the
    trust domain.

7.  Client extracts the `dynamic_ssf_stream` URL and subscribes
    to receive AIP-Dynamic updates.

8.  Client (optionally) fetches AIP-Dynamic immediately via the
   polling fallback endpoint.

### 7.5.  Cross-Domain Resolution via WebFinger

For cross-domain resolution, the protocol uses WebFinger with a
custom resource type.

#### 7.5.1.  WebFinger Query

```
GET https://<trusted-domain>/.well-known/webfinger?
  resource=aip:<agent-id>&
  rel=urn:ietf:params:aip:profile
```

Parameters:
-  resource:  The agent_id prefixed with "aip:".
-  rel:  The relationship type for AIP profile discovery.

#### 7.5.2.  WebFinger Response

```json
{
  "subject": "aip:wimse://trust.example.com/agents/...",
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
  ]
}
```

The `href` values point to the AIP Registry endpoints in the
trusted domain.

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
:  Unix timestamp when this delegation was created.

scope (REQUIRED):
:  Space-delimited list of scopes delegated.  Each scope MUST be
   a subset of the delegator's available scopes.

purpose (REQUIRED):
:  Human-readable description of the delegation purpose.

constraints (OPTIONAL):
:  Additional constraints on the delegation.

jti (REQUIRED):
:  Unique identifier for this delegation step.  Used for
   deduplication and audit.

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
delegated authorization.

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
    previous step's scope.

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

## 9.  Cross-Domain AIP Projection

### 9.1.  Projection Levels

When an AIP document is shared across trust domain boundaries, it
is often inappropriate to disclose the full document due to
privacy, security, or competitive concerns.  AIP supports three
projection levels:

Minimal Projection:
:  Reveals only the minimum information necessary for basic
   identity recognition and trust assessment:

   -  agent_id (without full URI path if desired)
   -  agent_type
   -  capabilities.declared (capability identifiers only, without
      scope details or risk levels)
   -  attestation.verification_endpoint (for cross-domain
      attestation verification)
   -  lifecycle_state

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
  "agent_id": "<agent_id to project>"
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

requester_purpose (RECOMMENDED):
:  Description of why this projection is needed.  The asserting
   domain's policy MAY require this for certain projection levels.

agent_id (REQUIRED):
:  The `agent_id` for which projection is requested.

Response (200 OK):
```json
{
  "level_granted": "standard",
  "fields_included": [...],
  "excluded_fields": [...],
  "aip_projection": {"agent_type":"coding","capabilities":{"declared":[{"capability":"file.read"}]}}
}
```

If the projection request cannot be granted:
-  403 Forbidden:  Projection request denied (insufficient trust,
    policy violation).
-  417 Expectation Failed:  Some requested fields unavailable,
    level adjustment suggested in the `level_granted` field (which
    MUST be lower than requested for this case).

### 9.3.  Field Visibility Rules

This specification provides a reference implementation of a
visibility policy.  Implementations MAY define their own policies
but MUST NOT disclose more information than the reference policy
allows at each projection level.

The reference visibility rules:

| Field                    | Minimal | Standard | Full |
|-------------------------|---------|----------|------|
| agent_id                | Full    | Full     | Full |
| agent_type              | Yes     | Yes      | Yes |
| owner_binding.owner_id  | No      | No       | Yes |
| owner_binding.binding_* | No      | Yes      | Yes |
| capabilities.declared   | Id only | Full     | Full |
| capabilities.restricted | No      | Id only  | Yes |
| governance.sponsor      | No      | No       | Yes |
| governance.compliance   | No      | Optional | Yes |
| integrity.composite_hash| No      | Yes      | Yes |
| attestation.token       | No      | No       | Yes |
| credential_lifecycle    | Expiry  | Full     | Full |
| observability.internal  | No      | No       | Yes |

"Id only" means only the `capability` identifier is included,
without `scope`, `risk_level`, or `mcp_tool_ref`.

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
   typically require re-verification or re-authorization.

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
  "aip_ref": "https://registry.example.com/agents/agent-123"
}
```

The resource server retrieves the AIP using the `aip_ref` and
uses the metadata for authorization decisions.

### 11.2.  Integration with OIDC and OIDC-A

AIP integrates with OpenID Connect [OIDC] and OpenID Connect for
Agents [OIDC-A].

Claim Mapping:

AIP fields can be mapped to OIDC-A claims:

| AIP Field                    | OIDC-A Claim              |
|------------------------------|---------------------------|
| agent_type                   | agent_type                |
| agent_model                  | agent_model               |
| agent_provider               | agent_provider            |
| agent_instance_id            | agent_instance_id         |
| owner_binding.delegation_chain| delegation_chain         |
| capabilities.oidc_a_format   | agent_capabilities        |
| attestation                  | agent_attestation         |

Token Integration:

AIP information can be embedded in the OIDC ID Token or Access
Token as claims.  Two approaches are supported:

Approach 1 — Inline Claims:
All relevant AIP fields are included as claims in the token.
This increases token size but avoids separate document fetch.

Approach 2 — Reference Claim:
Only the `aip_ref` is included in the token.  The consumer fetches
the full AIP when needed.  This keeps tokens compact and allows
AIP updates without requiring new tokens.

Discovery Integration:

AIP's `observability.discovery_endpoints` aligns with OIDC-A's
discovery mechanism.  The `.well-known/aip-configuration` endpoint
can be co-located with the OIDC discovery endpoint.

### 11.3.  Integration with draft-liu AOAT Framework

The AOAT framework [I-D.liu-agent-operation-authorization]
defines an `agent_identity` claim with seven baseline fields.

Mapping:

| AIP Field                              | AOAT agent_identity Field |
|----------------------------------------|---------------------------|
| profile_version                        | version                   |
| agent_id (UUID portion)                | id                        |
| owner_binding.owner_id                 | issuedTo                  |
| agent_id (trust domain portion)        | issuer                    |
| credential_lifecycle.primary_credential.issued_at | issuanceDate |
| credential_lifecycle.primary_credential.issued_at | validFrom   |
| credential_lifecycle.primary_credential.expires_at | expires    |
| agent_id (version portion)             | version                   |
| framework.name + agent_type            | issuedFor.client          |
| attestation.attestation_results.platform.namespace | issuedFor.clientInstance |

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
    "issuedFor": {"id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000", "type": "VerifiableCredential"}},
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
  "required_autonomy_level": "human_on_the_loop"
}
```

The MCP Server enforces authorization based on the AIP.

### 11.5.  Integration with A2A (Agent-to-Agent Protocol)

AIP supports agent-to-agent identity verification for protocols
like A2A.

Handshake Integration:

In an A2A handshake, agents can exchange AIP references:

```
Agent A -> Agent B: HELLO aip:wimse://trust.example.com/agents/agent-a
Agent B -> Agent A: HELLO aip:wimse://trust.example.com/agents/agent-b
Agent A -> Agent B: AIP_REF https://registry.example.com/agents/agent-a
Agent B -> Agent A: AIP_REF https://registry.example.com/agents/agent-b
```

Each agent fetches the other's AIP, verifies the signature, and
evaluates trust before proceeding.

### 11.6.  Integration with OpenID Shared Signals Framework

AIP integrates with OpenID SSF [RFC 8414] for real-time event
distribution.

Event Types:

AIP defines the following SSF event types:

-  aip.lifecycle_state_changed
-  aip.credential_rotated
-  aip.attestation_updated
-  aip.trust_level_changed
-  aip.integrity_failure
-  aip.policy_violation

Event Stream:

The `observability.ssf_config` object contains the stream IDs
for subscribing to these events.  Event payloads follow the SSF
event format.

## 12.  Security Considerations

### 12.1.  AIP Document Forgery

All AIP-Static documents MUST be cryptographically signed using
JWS [RFC 7515] with secure algorithms (RS256 or ES256 minimum).
The signature MUST cover the entire AIP-Static object.

Consumers MUST verify the signature before trusting any AIP
claims.  The verification key MUST be obtained from the Identity
Server's JWKS endpoint via HTTPS with certificate pinning where
possible.

### 12.2.  Delegation Chain Attacks

Delegation chains are a potential attack vector.  Implementations
MUST enforce all validation rules defined in Section 8.4.

Specifically, implementations MUST protect against:

(a) Privilege Escalation:  Scope narrowing at each step MUST be
    enforced.  A delegatee MUST NOT receive broader capabilities
    than the delegator.

(b) Excessive Depth:  Delegation depth limits MUST be strictly
    enforced.

(c) Circular Delegation:  Implementations MUST detect cycles in
    delegation chains.  A chain that revisits an `agent_id` is
    invalid.

(d) Stale Delegations:  Delegation steps MUST have expiration
    times.  Expired steps MUST be ignored.

### 12.3.  Integrity Bypass

Attackers MAY attempt to bypass integrity checks by:

(a) Modifying the agent configuration and providing a forged
    integrity hash.  This is prevented by the JWS signature on
    AIP-Static.

(b) Modifying the integrity verification endpoint to return
    false positive results.  Implementations MUST use
    certificate pinning for integrity verification endpoints.

(c) Exploiting timing windows between configuration change and
    verification.  Implementations SHOULD perform verification
    synchronously for critical operations and SHOULD monitor for
    rapid configuration changes.

### 12.4.  Prompt Injection and Intent Deviation

AIP's integrity model provides defense against prompt injection
by detecting unexpected changes to prompt templates.  However,
sophisticated attacks MAY evade detection by keeping semantic
similarity high while subtly altering behavior.

Implementations SHOULD complement AIP integrity with:

(a) Intent Verification:  The Authorization Server SHOULD verify
    that each operation request is semantically consistent with the
    original user intent.  This can be done by hashing the user's
    natural language request and including it in the operation
    proposal.

(b) Behavioral Monitoring:  Real-time behavioral anomaly
    detection (see Section 4.11) can detect subtle behavioral
    shifts that integrity checks miss.

### 12.5. Revocation Timeliness

Revocation MUST be timely to limit the impact of compromised
agents.  Implementations MUST:

(a) Use short-lived credentials as recommended by AIP lifecycle
    policies (default rotation interval: PT1H).

(b) Implement push-based revocation via OpenID SSF rather than
    relying solely on polling.

(c) Support the emergency kill switch endpoint for immediate
    revocation in critical situations.

(d) Implement cache invalidation for AIP-Static when revocation
    occurs.  The ETag mechanism with conditional requests is
    RECOMMENDED.

### 12.6.  Cross-Domain Information Leakage

AIP projection (Section 9) is designed to minimize information
leakage.  Implementations MUST:

(a) Reject projection requests that do not meet the trust policy
    for the requested projection level.

(b) Log all projection requests for audit purposes.

(c) Implement rate limiting on projection endpoints to prevent
    enumeration attacks.

### 12.7. Trust Anchor Compromise

If the Identity Server's signing key is compromised, all AIP
documents signed with that key become untrustworthy.  Implementations
MUST:

(a) Implement key rotation mechanisms.  The JWKS endpoint MUST
    support multiple signing keys with key IDs.

(b) When a key is compromised, publish a revocation event via SSF
    indicating the compromised key ID.

(c) Consumers MUST check the revocation event stream and reject
    AIP documents signed with revoked keys.

(d) Consider implementing a key compromise recovery mechanism
    (e.g., re-signing all AIP documents with a new key).

## 13.  IANA Considerations

### 13.1.  AIP Media Type Registration

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

### 13.2.  AIP Well-Known URI Registration

This specification requests registration of the following well-known
URI:

Well-known URI suffix:  aip-configuration
Specification document(s):  This document, Section 7.2
Person & email address to contact for further information:
    [TBD - Working Group Chair]

### 13.3.  AIP Field Registry

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

### 13.4.  Agent Type Registry

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

## 14.  References

### 14.1.  Normative References

[ISO.8601.2004]
    International Organization for Standardization, "Data elements
    and interchange formats — Information interchange —
    Representation of dates and times", ISO 8601:2004, 2004.

[OIDC]
    Hardt, D., "The OAuth 2.0 Authorization Framework: Bearer
    Token Usage", RFC 6750, October 2012.

[OIDC-A]
    [TBD - OpenID Connect for Agents specification]

[OIDC-JWT]
    Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token
    (JWT)", RFC 7519, May 2015.

[OIDC-JWS]
    Jones, M., "JSON Web Signature (JWS)", RFC 7515, May 2015.

[OIDC-JWKS]
    Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.

[RFC2119]
    Bradner, S., "Key words for use in RFCs to Indicate
    Requirement Levels", BCP 14, RFC 2119, March 1997.

[RFC3986]
    Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
    Resource Identifier (URI): Generic Syntax", STD 66,
    RFC 3986, January 2005.

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

[RFC8414]
    Jones, M., Sakimura, N., and J. Bradley, "OpenID Connect
    Discovery 1.0", RFC 8414, June 2018.

[RFC8693]
    Lodderstedt, T., Ed., "OAuth 2.0 Token Exchange", RFC 8693,
    February 2020.

[RFC8126]
    Cotton, M., Leiba, B., and T. Narten, "Guidelines for
    Writing an IANA Considerations Section in RFCs", BCP 26,
    RFC 8126, June 2017.

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

### 14.2.  Informative References

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
        "delegated_at": 1714348800,
        "scope": "code.execute file.read",
        "purpose": "Code assistance",
        "constraints": {
          "max_duration": 7200,
          "allowed_resources": ["/workspace/**"]
        },
        "jti": "step-unique-id-123"
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
    "timestamp": 1714348800,
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
  "lifecycle_state": "active",
  "extensions": {
    "organization": {
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
| framework.capabilities                            | agent_capabilities         |

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

---

## Authors' Addresses

[TBD - Working Group Authors]

This document is a product of the IETF Agent Identity Working Group.
