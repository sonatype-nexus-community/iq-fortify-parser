
package com.sonatype.ssc.integration.fortify.model.PolicyViolation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "policyId",
    "policyName",
    "policyThreatCategory",
    "policyThreatLevel",
    "policyViolationId",
    "waived",
    "grandfathered",
    "constraints"
})
public class Violation {

    @JsonProperty("policyId")
    private String policyId;
    @JsonProperty("policyName")
    private String policyName;
    @JsonProperty("policyThreatCategory")
    private String policyThreatCategory;
    @JsonProperty("policyThreatLevel")
    private Integer policyThreatLevel;
    @JsonProperty("policyViolationId")
    private String policyViolationId;
    @JsonProperty("waived")
    private Boolean waived;
    @JsonProperty("grandfathered")
    private Boolean grandfathered;
    @JsonProperty("constraints")
    private List<Constraint> constraints = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("policyId")
    public String getPolicyId() {
        return policyId;
    }

    @JsonProperty("policyId")
    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    @JsonProperty("policyName")
    public String getPolicyName() {
        return policyName;
    }

    @JsonProperty("policyName")
    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }

    @JsonProperty("policyThreatCategory")
    public String getPolicyThreatCategory() {
        return policyThreatCategory;
    }

    @JsonProperty("policyThreatCategory")
    public void setPolicyThreatCategory(String policyThreatCategory) {
        this.policyThreatCategory = policyThreatCategory;
    }

    @JsonProperty("policyThreatLevel")
    public Integer getPolicyThreatLevel() {
        return policyThreatLevel;
    }

    @JsonProperty("policyThreatLevel")
    public void setPolicyThreatLevel(Integer policyThreatLevel) {
        this.policyThreatLevel = policyThreatLevel;
    }

    @JsonProperty("policyViolationId")
    public String getPolicyViolationId() {
        return policyViolationId;
    }

    @JsonProperty("policyViolationId")
    public void setPolicyViolationId(String policyViolationId) {
        this.policyViolationId = policyViolationId;
    }

    @JsonProperty("waived")
    public Boolean getWaived() {
        return waived;
    }

    @JsonProperty("waived")
    public void setWaived(Boolean waived) {
        this.waived = waived;
    }

    @JsonProperty("grandfathered")
    public Boolean getGrandfathered() {
        return grandfathered;
    }

    @JsonProperty("grandfathered")
    public void setGrandfathered(Boolean grandfathered) {
        this.grandfathered = grandfathered;
    }

    @JsonProperty("constraints")
    public List<Constraint> getConstraints() {
        return constraints;
    }

    @JsonProperty("constraints")
    public void setConstraints(List<Constraint> constraints) {
        this.constraints = constraints;
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
