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
package com.alibaba.openagentauth.sample.idp.agent;

import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Sample Agent Identity Provider Application.
 * <p>
 * This is a demonstration application that implements an Agent Identity Provider (Agent IDP)
 * following the WIMSE (Workload Identity Management for Service Endpoints) protocol.
 * The Agent IDP is responsible for managing agent workload identities and issuing
 * Workload Identity Tokens (WIT) that contain both standard workload identity
 * and agent-specific claims.
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li><b>Agent Workload Management:</b> Creates and manages virtual workloads for agent operations</li>
 *   <li><b>WIT Issuance:</b> Issues Workload Identity Tokens with agent identity claims</li>
 *   <li><b>Identity Binding:</b> Binds agent identity to user identity for traceability</li>
 *   <li><b>Agent Lifecycle:</b> Manages the lifecycle of agent workloads</li>
 * </ul>
 * <p>
 * <b>Key Features:</b></p>
 * <ul>
 *   <li>WIMSE-compliant workload identity management</li>
 *   <li>Workload Identity Token (WIT) issuance</li>
 *   <li>User-to-Agent identity binding for audit trail</li>
 *   <li>Temporary key pair generation for each workload</li>
 *   <li>Workload lifecycle management (create, revoke, query)</li>
 * </ul>
 * <p>
 * <b>Port:</b> 8082
 * </p>
 * <p>
 * <b>REST Endpoints:</b></p>
 * <ul>
 *   <li>POST /api/v1/workloads - Create a new agent workload</li>
 *   <li>POST /api/v1/workloads/token/issue - Issue WIT with automatic workload management</li>
 *   <li>POST /api/v1/workloads/issue - Issue WIT for a specific workload</li>
 *   <li>POST /api/v1/workloads/revoke - Revoke a workload</li>
 *   <li>POST /api/v1/workloads/get - Get workload information</li>
 *   <li>GET /.well-known/jwks.json - JWKS endpoint for WIT verification</li>
 *   <li>GET /.well-known/openid-configuration - OpenID configuration</li>
 * </ul>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>WIMSE Draft - Workload Identity Management for Service Endpoints</li>
 *   <li>OAuth 2.0 - Authorization Framework</li>
 *   <li>OpenID Connect - Identity Layer</li>
 *   <li>JWT/JWS/JWE - JSON Web Tokens</li>
 * </ul>
 *
 * @see AgentIdentityProvider
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">WIMSE Draft</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @since 1.0
 */
@SpringBootApplication
public class SampleAgentIdpApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleAgentIdpApplication.class, args);
    }
}