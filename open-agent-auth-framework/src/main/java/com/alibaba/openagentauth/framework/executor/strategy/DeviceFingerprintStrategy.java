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
package com.alibaba.openagentauth.framework.executor.strategy;

/**
 * Strategy for generating device fingerprints.
 * <p>
 * This interface allows customization of device fingerprint generation
 * logic, enabling different implementations based on security requirements
 * and operational contexts.
 * </p>
 *
 * @since 1.0
 */
@FunctionalInterface
public interface DeviceFingerprintStrategy {
    
    /**
     * Generates a device fingerprint.
     * 
     * @param workloadId the workload ID
     * @return the device fingerprint
     */
    String generate(String workloadId);
}
