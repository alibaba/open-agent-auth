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
package com.alibaba.openagentauth.sample.authz;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Sample Authorization Server Application.
 * <p>
 * This application demonstrates a complete implementation of an Authorization Server
 * following the Agent Operation Authorization protocol. It provides the core OAuth 2.0
 * endpoints including PAR, Authorization, Token, and DCR, integrated with the Open
 * Agent Auth framework.
 * </p>
 * <p>
 * <b>Port:</b> 8085
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li>Process Pushed Authorization Requests (PAR) - RFC 9126</li>
 *   <li>Handle OAuth 2.0 Authorization Flow - RFC 6749</li>
 *   <li>Issue Agent Operation Authorization Tokens (AOAT)</li>
 *   <li>Support Dynamic Client Registration (DCR) - RFC 7591</li>
 *   <li>Validate WIT and User Identity Tokens</li>
 *   <li>Register OPA Policies for authorization</li>
 * </ul>
 *
 * @since 1.0
 */
@SpringBootApplication
public class SampleAuthorizationServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleAuthorizationServerApplication.class, args);
    }
}