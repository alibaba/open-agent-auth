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
package com.alibaba.openagentauth.core.protocol.wimse.workload.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response DTO for WIT issuance.
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssueWitResponse {

    @JsonProperty("wit")
    private String wit;

    @JsonProperty("error")
    private String error;

    public String getWit() {
        return wit;
    }

    public void setWit(String wit) {
        this.wit = wit;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static IssueWitResponse error(String error) {
        IssueWitResponse response = new IssueWitResponse();
        response.error = error;
        return response;
    }

    public static class Builder {
        private String wit;

        public Builder wit(String wit) {
            this.wit = wit;
            return this;
        }

        public IssueWitResponse build() {
            IssueWitResponse response = new IssueWitResponse();
            response.wit = this.wit;
            return response;
        }
    }
}
