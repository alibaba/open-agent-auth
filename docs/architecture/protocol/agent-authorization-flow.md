# Agent Authorization Flow

This document describes the complete Agent Operation Authorization (AOA) protocol flow,
including all six phases from user authentication to tool execution.

> **Source**: Extracted from `Agent.java` interface Javadoc to keep the interface concise
> while preserving the detailed protocol documentation.

## Phase 1: User Authentication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Phase 1: User Authentication                             │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────┐        ┌──────────────┐      ┌──────────────┐        ┌──────────────────┐
   │   User   │        │ User's Agent │      │ Agent Actor  │        │ Agent User IDP   │
   └────┬─────┘        └──────┬───────┘      └──────┬───────┘        └────────┬─────────┘
        │                     │                     │                         │
        │ 1. User Input       │                     │                         │
        │────────────────────>│                     │                         │
        │  ("Buy winter clothing advice")           │                         │
        │                     │                     │                         │
        │                     │ 2. initiateAuthorization (redirectUri, state) │
        │                     │────────────────────>│                         │
        │                     │                     │                         │
        │                     │ 3. Return Auth URL  │                         │
        │                     │<────────────────────│                         │
        │                     │ (Agent Actor builds auth URL locally)         │
        │                     │                     │                         │
        │ 4. Redirect to      │                     │                         │
        │<────────────────────│                     │                         │
        │   Agent User IDP    │                     │                         │
        │   [USER ACTION]     │                     │                         │
        │                     │                     │                         │
        │ 5. User Login       │                     │                         │
        │────────────────────────────────────────────────────────────────────>│
        │   (credentials)     │                     │                         │
        │   [USER ACTION]     │                     │                         │
        │                     │                     │                         │
        │ 6a. Redirect User Agent (with Auth Code)  │                         │
        │<────────────────────────────────────────────────────────────────────│
        │   [HTTP 302]        │                     │                         │
        │ 6b. Callback URL    │                     │                         │
        │────────────────────>│                     │                         │
        │   (User Agent auto-access)                │                         │
        │                     │                     │                         │
        │                     │ 7. exchangeCodeForToken (code, state)         │
        │                     │────────────────────>│                         │
        │                     │                     │                         │
        │                     │                     │ 7a. Exchange Code for Token
        │                     │                     │────────────────────────>│
        │                     │                     │ 7b. Return ID Token     │
        │                     │                     │<────────────────────────│
        │                     │ 8. Return ID Token  │                         │
        │                     │<────────────────────│                         │
        │                     │   (to User's Agent backend)                   │
        │                     │                     │                         │
```

### System Interactions

1. User inputs prompt to User's Agent (e.g., "Buy winter clothing advice")
2. User's Agent calls Agent Actor `initiateAuthorization()` to get authorization URL
3. Agent Actor returns authorization URL to User's Agent
4. User's Agent redirects user to Agent User IDP
5. User logs in at Agent User IDP with credentials
6. Agent User IDP returns authorization code via callback
7. User's Agent calls Agent Actor `exchangeCodeForToken()` with authorization code
8. Agent Actor exchanges code for ID Token and returns AuthenticationResponse

## Phase 2: Workload Creation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Phase 2: Workload Creation                               │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────────┐      ┌──────────────┐      ┌─────────────┐
   │ User's Agent │      │ Agent Actor  │      │ Agent IDP   │
   └──────┬───────┘      └──────┬───────┘      └────────┬────┘
          │                     │                       │
          │ 1. createWorkload   │                       │
          │────────────────────>│                       │
          │                     │                       │
          │                     │ 2. Create Workload    │
          │                     │──────────────────────>│
          │                     │   (with user ID)      │
          │                     │                       │
          │                     │ 3. Return WIT         │
          │                     │<──────────────────────│
          │                     │   (with agent_id)     │
          │                     │                       │
          │ 4. Return           │                       │
          │    WorkloadContext  │                       │
          │<────────────────────│                       │
```

### System Interactions

1. User's Agent calls Agent Actor `issueWorkloadIdentityToken()`
2. Agent Actor creates workload via Agent IDP / WIMSE IDP
3. Agent IDP returns WIT (with agent_id)
4. Agent Actor returns WorkloadContext to User's Agent

## Phase 3: OAuth Client Registration (DCR)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│           Phase 3: OAuth Client Registration (DCR)                          │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────────┐         ┌──────────────┐      ┌──────────────────────┐
   │ User's Agent │         │ Agent Actor  │      │ Authorization Server │
   └──────┬───────┘         └──────┬───────┘      └──────────┬───────────┘
          │                        │                         │
          │ 1. registerOAuthClient │                         │
          │───────────────────────>│                         │
          │                        │                         │
          │                        │ 2. Register Client      │
          │                        │────────────────────────>│
          │                        │   (with WIT as client_assertion)
          │                        │                         │
          │                        │ 3. Validate WIT & Return client_id
          │                        │<────────────────────────│
          │                        │                         │
          │                        │                         │
          │ 4. Return DcrResponse  │                         │
          │<───────────────────────│                         │
```

### System Interactions

1. User's Agent calls Agent Actor `registerOAuthClient()`
2. Agent Actor registers OAuth client with Authorization Server using WIT as client_assertion
3. Authorization Server validates WIT and returns DcrResponse with client_id (WIT.sub)
4. Agent Actor returns DcrResponse to User's Agent

## Phase 4: Authorization Request

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              Phase 4: Authorization Request (PAR Flow)                      │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────────┐        ┌──────────────┐       ┌──────────────────────┐
   │ User's Agent │        │ Agent Actor  │       │ Authorization Server │
   └──────┬───────┘        └──────┬───────┘       └──────────┬───────────┘
          │                       │                          │
          │ 1. submitParRequest   │                          │
          │──────────────────────>│                          │
          │                       │                          │
          │                       │ 2. Submit PAR-JWT        │
          │                       │─────────────────────────>│
          │                       │   (with WIT + Prompt VC) │
          │                       │                          │
          │                       │ 3. Validate & Return     │
          │                       │<─────────────────────────│
          │                       │    request_uri           │
          │                       │                          │
          │ 4. Return ParResponse │                          │
          │<──────────────────────│                          │
          │                       │                          │
          │ 5. generateAuthUrl    │                          │
          │──────────────────────>│                          │
          │                       │                          │
          │ 6. Return Auth URL    │                          │
          │<──────────────────────│                          │
```

### System Interactions

1. User's Agent calls Agent Actor `submitParRequest()`
2. Agent Actor submits PAR-JWT to Authorization Server (with WIT + Prompt VC)
3. Authorization Server validates and returns request_uri
4. Agent Actor returns ParResponse to User's Agent
5. User's Agent calls Agent Actor `generateAuthorizationUrl()`
6. Agent Actor returns authorization URL

## Phase 5: User Authorization

```
┌─────────────────────────────────────────────────────────────────────────────┐
│              Phase 5: User Authorization (OAuth 2.0 Flow)                   │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────┐       ┌──────────────┐    ┌──────────────────────┐   ┌──────────────┐
   │   User   │       │ User's Agent │    │ Authorization Server │   │ AS User IDP  │
   └────┬─────┘       └──────┬───────┘    └────────┬─────────────┘   └────────┬─────┘
        │                    │                     │                          │
        │ 1. Redirect        │                     │                          │
        │<───────────────────│                     │                          │
        │   (to Auth URL)    │                     │                          │
        │   [USER ACTION]    │                     │                          │
        │                    │                     │                          │
        │ 2. User Visits     │                     │                          │
        │─────────────────────────────────────────>│                          │
        │   Authz Server     │                     │                          │
        │   [USER ACTION]    │                     │                          │
        │                    │                     │                          │
        │                    │                     │ 3. Authenticate User     │
        │                    │                     │─────────────────────────>│
        │                    │                     │                          │
        │                    │                     │ 4. Return ID Token       │
        │                    │                     │<─────────────────────────│
        │                    │                     │                          │
        │ 5. User Grants     │                     │                          │
        │─────────────────────────────────────────>│                          │
        │   Authorization    │                     │                          │
        │   [USER ACTION]    │                     │                          │
        │                    │                     │                          │
        │                    │                     │ 6. Callback to Agent     │
        │                    │<────────────────────│                          │
        │                    │   (with auth code)  │                          │
```

### System Interactions

1. User's Agent redirects user to authorization URL
2. User visits Authorization Server
3. Authorization Server authenticates user via AS User IDP
4. AS User IDP returns ID Token
5. User grants authorization at Authorization Server
6. Authorization Server sends callback with authorization code to User's Agent

## Phase 6: Token Exchange & Tool Execution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│        Phase 6: Token Exchange & Tool Execution                             │
└─────────────────────────────────────────────────────────────────────────────┘

   ┌──────────────┐      ┌──────────────┐          ┌──────────────────────┐
   │ User's Agent │      │ Agent Actor  │          │ Authorization Server │
   └──────┬───────┘      └──────┬───────┘          └────────┬─────────────┘
          │                     │                           │
          │ 1. handleCallback   │                           │
          │────────────────────>│                           │
          │                     │                           │
          │                     │ 2. Exchange Code for AOAT │
          │                     │──────────────────────────>│
          │                     │                           │
          │                     │                           │
          │                     │ 3. Return AOAT            │
          │                     │<──────────────────────────│
          │                     │                           │
          │ 4. executeTool      │                           │
          │────────────────────>│                           │
          │                     │                           │
          │ 5. Return Result    │                           │
          │<────────────────────│                           │
          │                     │                           │
          │ 6. clearContext     │                           │
          │────────────────────>│                           │
```

### System Interactions

1. User's Agent calls Agent Actor `handleAuthorizationCallback()`
2. Agent Actor exchanges authorization code for AOAT with Authorization Server
3. Authorization Server returns AOAT
4. User's Agent calls Agent Actor `prepareAuthorizationContext()`
5. User's Agent uses authorization context to execute tools via protocol adapters
6. User's Agent calls Agent Actor `clearAuthorizationContext()`
