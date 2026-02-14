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
package com.alibaba.openagentauth.sample.rs;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Sample Resource Server Application.
 * <p>
 * This is a demonstration application that implements a Resource Server
 * with MCP (Model Context Protocol) support. It provides a shopping service
 * with AI agent integration and five-layer verification architecture.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>MCP Server with Streamable HTTP transport</li>
 *   <li>Five-layer verification architecture (WIT, WPT, OAAT, Identity Consistency, OPA)</li>
 *   <li>Shopping service with product search, cart management, and order processing</li>
 *   <li>Integration with WIMSE (Workload Identity Management for Service Endpoints)</li>
 *   <li>Support for Agent Operation Authorization (AOA)</li>
 * </ul>
 * <p>
 * <b>Port:</b> 8086
 * </p>
 * <p>
 * <b>MCP Endpoint:</b> /mcp
 * </p>
 * <p>
 * <b>Registered Tools:</b></p>
 * <ul>
 *   <li>search_products - Search for products by category and keywords</li>
 *   <li>add_to_cart - Add products to shopping cart</li>
 *   <li>purchase_product - Purchase products from cart</li>
 *   <li>query_orders - Query order history</li>
 * </ul>
 *
 * @see <a href="https://modelcontextprotocol.io">Model Context Protocol</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials</a>
 */
@SpringBootApplication
@EnableConfigurationProperties
public class SampleResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(SampleResourceServerApplication.class, args);
    }
}