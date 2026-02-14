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
package com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link WorkloadIdentityProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(WorkloadIdentityProperties.class)
class WorkloadIdentityPropertiesTest {

    @Test
    void testDefaultValues() {
        WorkloadIdentityProperties properties = new WorkloadIdentityProperties();
        
        assertFalse(properties.isEnabled());
        assertNotNull(properties.getEndpoints());
        
        assertEquals("/api/v1/workloads/revoke", properties.getEndpoints().getWorkload().getRevoke());
        assertEquals("/api/v1/workloads/get", properties.getEndpoints().getWorkload().getGet());
        assertEquals("/api/v1/workloads/token/issue", properties.getEndpoints().getWorkload().getIssue());
    }

    @Test
    void testGetterSetter() {
        WorkloadIdentityProperties properties = new WorkloadIdentityProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties endpoints = new WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties();
        endpoints.setWorkload(new WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties.WorkloadEndpointPaths());
        endpoints.getWorkload().setRevoke("/custom/revoke");
        properties.setEndpoints(endpoints);
        assertEquals("/custom/revoke", properties.getEndpoints().getWorkload().getRevoke());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = WorkloadIdentityProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.capabilities.workload-identity", annotation.prefix());
    }

    @Test
    void testEndpointsProperties() {
        WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties endpoints = new WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties();
        WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties.WorkloadEndpointPaths workload = endpoints.getWorkload();
        
        workload.setRevoke("/custom/revoke");
        assertEquals("/custom/revoke", workload.getRevoke());
        
        workload.setGet("/custom/get");
        assertEquals("/custom/get", workload.getGet());
        
        workload.setIssue("/custom/token/issue");
        assertEquals("/custom/token/issue", workload.getIssue());
    }

    @Test
    void testBoundaryValues() {
        WorkloadIdentityProperties properties = new WorkloadIdentityProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.getEndpoints().getWorkload().setRevoke("");
        assertEquals("", properties.getEndpoints().getWorkload().getRevoke());
        
        properties.getEndpoints().getWorkload().setGet("/api/v1/workloads/custom-get");
        assertEquals("/api/v1/workloads/custom-get", properties.getEndpoints().getWorkload().getGet());
    }

    @Test
    void testPropertyIndependence() {
        WorkloadIdentityProperties properties1 = new WorkloadIdentityProperties();
        WorkloadIdentityProperties properties2 = new WorkloadIdentityProperties();
        
        properties1.setEnabled(true);
        assertFalse(properties2.isEnabled());
        
        properties1.getEndpoints().getWorkload().setRevoke("/custom");
        assertEquals("/api/v1/workloads/revoke", properties2.getEndpoints().getWorkload().getRevoke());
    }

    @Test
    void testEndpointPaths() {
        WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties endpoints = new WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties();
        WorkloadIdentityProperties.WorkloadIdentityEndpointsProperties.WorkloadEndpointPaths workload = endpoints.getWorkload();
        
        workload.setRevoke("/api/v1/workloads/revoke");
        assertTrue(workload.getRevoke().startsWith("/"));
        
        workload.setGet("/api/v1/workloads/get");
        assertTrue(workload.getGet().startsWith("/"));
        
        workload.setIssue("/api/v1/workloads/token/issue");
        assertTrue(workload.getIssue().startsWith("/"));
    }
}