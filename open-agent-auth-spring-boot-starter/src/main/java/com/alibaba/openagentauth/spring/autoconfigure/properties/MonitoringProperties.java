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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

/**
 * Monitoring configuration properties.
 * <p>
 * Controls metrics collection and distributed tracing for observability.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   monitoring:
 *     metrics:
 *       enabled: true
 *       export-prometheus: true
 *     tracing:
 *       enabled: false
 * </pre>
 *
 * @since 1.0
 */
public class MonitoringProperties {

    /**
     * Metrics configuration.
     * <p>
     * Controls the collection and export of application metrics.
     * </p>
     */
    private MetricsProperties metrics = new MetricsProperties();

    /**
     * Tracing configuration.
     * <p>
     * Controls distributed tracing for request tracking and analysis.
     * </p>
     */
    private TracingProperties tracing = new TracingProperties();

    /**
     * Gets the metrics configuration.
     *
     * @return the metrics properties
     */
    public MetricsProperties getMetrics() {
        return metrics;
    }

    /**
     * Sets the metrics configuration.
     *
     * @param metrics the metrics properties to set
     */
    public void setMetrics(MetricsProperties metrics) {
        this.metrics = metrics;
    }

    /**
     * Gets the tracing configuration.
     *
     * @return the tracing properties
     */
    public TracingProperties getTracing() {
        return tracing;
    }

    /**
     * Sets the tracing configuration.
     *
     * @param tracing the tracing properties to set
     */
    public void setTracing(TracingProperties tracing) {
        this.tracing = tracing;
    }

    /**
     * Metrics configuration properties.
     * <p>
     * Controls application metrics collection and export.
     * </p>
     */
    public static class MetricsProperties {

        /**
         * Whether metrics collection is enabled.
         * <p>
         * When enabled, the application will collect runtime metrics
         * such as request counts, response times, and error rates.
         * </p>
         */
        private boolean enabled = true;

        /**
         * Whether to export metrics to Prometheus.
         * <p>
         * When enabled, metrics will be exposed in Prometheus format
         * at the /actuator/prometheus endpoint.
         * </p>
         */
        private boolean exportPrometheus = true;

        /**
         * Gets whether metrics collection is enabled.
         *
         * @return whether metrics collection is enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether metrics collection is enabled.
         *
         * @param enabled whether to enable metrics collection
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets whether to export metrics to Prometheus.
         *
         * @return whether Prometheus export is enabled
         */
        public boolean isExportPrometheus() {
            return exportPrometheus;
        }

        /**
         * Sets whether to export metrics to Prometheus.
         *
         * @param exportPrometheus whether to enable Prometheus export
         */
        public void setExportPrometheus(boolean exportPrometheus) {
            this.exportPrometheus = exportPrometheus;
        }
    }

    /**
     * Tracing configuration properties.
     * <p>
     * Controls distributed tracing for request tracking.
     * </p>
     */
    public static class TracingProperties {

        /**
         * Whether distributed tracing is enabled.
         * <p>
         * When enabled, the application will generate and export trace spans
         * for distributed request tracking.
         * </p>
         */
        private boolean enabled = false;

        /**
         * Gets whether distributed tracing is enabled.
         *
         * @return whether distributed tracing is enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether distributed tracing is enabled.
         *
         * @param enabled whether to enable distributed tracing
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}
