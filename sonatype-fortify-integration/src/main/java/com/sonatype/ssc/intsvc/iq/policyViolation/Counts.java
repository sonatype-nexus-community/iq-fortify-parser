
package com.sonatype.ssc.intsvc.iq.policyViolation;

import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "partiallyMatchedComponentCount",
    "exactlyMatchedComponentCount",
    "totalComponentCount",
    "grandfatheredPolicyViolationCount"
})
public class Counts {

    @JsonProperty("partiallyMatchedComponentCount")
    private Integer partiallyMatchedComponentCount;
    @JsonProperty("exactlyMatchedComponentCount")
    private Integer exactlyMatchedComponentCount;
    @JsonProperty("totalComponentCount")
    private Integer totalComponentCount;
    @JsonProperty("grandfatheredPolicyViolationCount")
    private Integer grandfatheredPolicyViolationCount;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("partiallyMatchedComponentCount")
    public Integer getPartiallyMatchedComponentCount() {
        return partiallyMatchedComponentCount;
    }

    @JsonProperty("partiallyMatchedComponentCount")
    public void setPartiallyMatchedComponentCount(Integer partiallyMatchedComponentCount) {
        this.partiallyMatchedComponentCount = partiallyMatchedComponentCount;
    }

    @JsonProperty("exactlyMatchedComponentCount")
    public Integer getExactlyMatchedComponentCount() {
        return exactlyMatchedComponentCount;
    }

    @JsonProperty("exactlyMatchedComponentCount")
    public void setExactlyMatchedComponentCount(Integer exactlyMatchedComponentCount) {
        this.exactlyMatchedComponentCount = exactlyMatchedComponentCount;
    }

    @JsonProperty("totalComponentCount")
    public Integer getTotalComponentCount() {
        return totalComponentCount;
    }

    @JsonProperty("totalComponentCount")
    public void setTotalComponentCount(Integer totalComponentCount) {
        this.totalComponentCount = totalComponentCount;
    }

    @JsonProperty("grandfatheredPolicyViolationCount")
    public Integer getGrandfatheredPolicyViolationCount() {
        return grandfatheredPolicyViolationCount;
    }

    @JsonProperty("grandfatheredPolicyViolationCount")
    public void setGrandfatheredPolicyViolationCount(Integer grandfatheredPolicyViolationCount) {
        this.grandfatheredPolicyViolationCount = grandfatheredPolicyViolationCount;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
