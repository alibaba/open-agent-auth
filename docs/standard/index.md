---
title: Standards & Proposals
---

# Standards & Proposals

This section hosts the **Specification Enhancement Proposals (SEPs)** and **IETF-related standards** for the Open Agent Auth project. Content is organized into two categories:

- **SEP (Specification Enhancement Proposals)** — Project-owned proposals for new specifications, protocol extensions, or significant architectural changes
- **IETF Standards & Drafts** — External IETF standards and Internet-Drafts that the project references or contributes to

## What is a SEP?

A **Specification Enhancement Proposal (SEP)** is a design document that describes a new specification, protocol extension, or significant architectural change for the Open Agent Auth ecosystem. SEPs follow a structured lifecycle inspired by established open-source governance models such as [PEP (Python)](https://peps.python.org/), [JEP (OpenJDK)](https://openjdk.org/jeps/0), and [KEP (Kubernetes)](https://github.com/kubernetes/enhancements/tree/master/keps).

## SEP Lifecycle

```
┌─────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────┐    ┌─────────┐
│  Draft  │───▶│  Review  │───▶│  Last Call   │───▶│ Accepted │───▶│  Final  │
└─────────┘    └──────────┘    └──────────────┘    └──────────┘    └─────────┘
     │               │                                                  │
     │               ▼                                                  │
     │         ┌────────────┐                                           │
     └────────▶│  Rejected  │                                           │
               └────────────┘                                           │
                                                                        ▼
                                                                  ┌────────────┐
                                                                  │ Superseded │
                                                                  └────────────┘
```

| Status | Description |
|--------|-------------|
| **Draft** | Initial proposal, open for community feedback via GitHub Issue and PR |
| **Review** | Formal review period; maintainers and community evaluate the proposal |
| **Last Call** | Final comment period (typically 14 days) before acceptance |
| **Accepted** | Approved by maintainers; implementation may proceed |
| **Final** | Specification is stable and published |
| **Rejected** | Proposal was not accepted (with documented rationale) |
| **Superseded** | Replaced by a newer SEP |

## How to Submit a SEP

1. **Open a GitHub Issue** using the [`SEP Proposal`](https://github.com/alibaba/open-agent-auth/issues/new?template=sep_proposal.md) template
   - Title format: `[SEP-XXXX] Descriptive Title`
   - Fill in the Summary, Motivation, Scope, and Related Work sections
2. **Fork the repository** and create a branch: `docs/sep-XXXX-short-title`
3. **Write the SEP document** following the [SEP Template](#sep-document-template) and place it in `docs/standard/sep/`
4. **Submit a Pull Request** referencing the tracking Issue
5. **Iterate on feedback** during the Review phase
6. **Maintainers decide** to accept, request changes, or reject

## SEP Document Template

Every SEP document should begin with a structured metadata header:

```markdown
---
sep: XXXX
title: "<Descriptive Title>"
status: Draft | Review | Last Call | Accepted | Final | Rejected | Superseded
type: Standards Track | Informational | Process
created: YYYY-MM-DD
updated: YYYY-MM-DD
authors:
  - name (affiliation) <email>
requires: [list of prerequisite SEP numbers, if any]
replaces: [SEP number, if any]
superseded-by: [SEP number, if any]
tracking-issue: "https://github.com/alibaba/open-agent-auth/issues/XXX"
---
```

## Active Proposals (SEP)

| SEP | Title | Status | Created |
|-----|-------|--------|---------|
| SEP-0001 | [Agent Identity Profile (AIP)](./sep/sep-0001-agent-identity-profile) | Draft | 2026-03-07 |

## IETF Standards & Drafts

| Standard | Description | Status |
|----------|-------------|--------|
| [draft-liu-agent-operation-authorization-01](./ietf/draft-liu-agent-operation-authorization-01.txt) | Agent Operation Authorization Protocol | IETF Internet-Draft |
