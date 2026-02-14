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
package com.alibaba.openagentauth.core.protocol.wimse.workload.client;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.RevokeWorkloadRequest;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * REST-based HTTP client implementation for Agent Identity Provider.
 * <p>
 * This implementation uses Java 11+ HttpClient to call Agent IDP services
 * via HTTP, following standard RESTful protocol design. It provides a clean
 * abstraction over HTTP communication with proper error handling.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b> All endpoints use POST method with parameters
 * in the request body, following WIMSE protocol recommendations for handling
 * workload identifiers as opaque strings that should not be exposed in URLs.
 * </p>
 *
 * @see WorkloadClient
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
public class RestWorkloadClient implements WorkloadClient {

    private static final Logger logger = LoggerFactory.getLogger(RestWorkloadClient.class);

    private final HttpClient httpClient;
    private final ServiceEndpointResolver serviceEndpointResolver;
    private final ObjectMapper objectMapper;

    /**
     * Creates a new RestAgentIdpHttpClient with default HttpClient.
     *
     * @param serviceEndpointResolver the service endpoint resolver
     */
    public RestWorkloadClient(ServiceEndpointResolver serviceEndpointResolver) {
        this(HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(Duration.ofSeconds(30))
                .build(), serviceEndpointResolver);
    }

    /**
     * Creates a new RestAgentIdpHttpClient with custom HttpClient.
     *
     * @param httpClient the HttpClient for HTTP calls
     * @param serviceEndpointResolver the service endpoint resolver
     */
    public RestWorkloadClient(HttpClient httpClient, ServiceEndpointResolver serviceEndpointResolver) {
        ValidationUtils.validateNotNull(httpClient, "HttpClient");
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");
        
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        
        logger.info("RestAgentIdpHttpClient initialized with service endpoint resolver");
    }


    @Override
    public IssueWitResponse issueWit(IssueWitRequest request)
        throws WorkloadCreationException, WorkloadNotFoundException {
        logger.debug("Issuing WIT via HTTP with automatic workload management");

        try {
            String url = serviceEndpointResolver.resolveConsumer("agent-idp", "workload.issue");
            String requestBody = objectMapper.writeValueAsString(request);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

            HttpResponse<String> httpResponse = httpClient.send(
                httpRequest,
                HttpResponse.BodyHandlers.ofString()
            );

            IssueWitResponse responseBody = objectMapper.readValue(
                httpResponse.body(),
                IssueWitResponse.class
            );

            if (responseBody == null) {
                throw new WorkloadNotFoundException("Empty response from Agent IDP");
            }

            if (!ValidationUtils.isNullOrEmpty(responseBody.getError())) {
                throw new WorkloadCreationException("Agent IDP returned error: " + responseBody.getError());
            }

            logger.info("Successfully issued WIT via HTTP with automatic workload management");
            return responseBody;

        } catch (WorkloadCreationException | WorkloadNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to issue WIT via HTTP: {}", e.getMessage(), e);
            throw new WorkloadCreationException("Failed to issue WIT: " + e.getMessage(), e);
        }
    }

    @Override
    public void revokeWorkload(String workloadId) throws WorkloadNotFoundException {
        logger.debug("Revoking workload via HTTP: {}", workloadId);
        
        try {
            String url = serviceEndpointResolver.resolveConsumer("agent-idp", "workload.revoke");
            
            RevokeWorkloadRequest request = RevokeWorkloadRequest.builder()
                    .workloadId(workloadId)
                    .build();
            
            String requestBody = objectMapper.writeValueAsString(request);
            
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();
            
            HttpResponse<String> httpResponse = httpClient.send(
                    httpRequest,
                    HttpResponse.BodyHandlers.ofString()
            );
            
            if (httpResponse.statusCode() == 404) {
                throw new WorkloadNotFoundException("Workload not found: " + workloadId);
            }
            
            logger.info("Successfully revoked workload via HTTP: {}", workloadId);
            
        } catch (WorkloadNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to revoke workload via HTTP: {}", e.getMessage(), e);
            throw new WorkloadNotFoundException("Failed to revoke workload: " + e.getMessage());
        }
    }
}