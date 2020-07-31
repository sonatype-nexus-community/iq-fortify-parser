
package com.sonatype.ssc.intsvc.model.scanhistory;

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
    "alerts",
    "affectedComponentCount",
    "criticalComponentCount",
    "severeComponentCount",
    "moderateComponentCount",
    "criticalPolicyViolationCount",
    "severePolicyViolationCount",
    "moderatePolicyViolationCount",
    "grandfatheredPolicyViolationCount"
})
public class PolicyEvaluationResult {

    @JsonProperty("alerts")
    private List<Object> alerts = null;
    @JsonProperty("affectedComponentCount")
    private Integer affectedComponentCount;
    @JsonProperty("criticalComponentCount")
    private Integer criticalComponentCount;
    @JsonProperty("severeComponentCount")
    private Integer severeComponentCount;
    @JsonProperty("moderateComponentCount")
    private Integer moderateComponentCount;
    @JsonProperty("criticalPolicyViolationCount")
    private Integer criticalPolicyViolationCount;
    @JsonProperty("severePolicyViolationCount")
    private Integer severePolicyViolationCount;
    @JsonProperty("moderatePolicyViolationCount")
    private Integer moderatePolicyViolationCount;
    @JsonProperty("grandfatheredPolicyViolationCount")
    private Integer grandfatheredPolicyViolationCount;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("alerts")
    public List<Object> getAlerts() {
        return alerts;
    }

    @JsonProperty("alerts")
    public void setAlerts(List<Object> alerts) {
        this.alerts = alerts;
    }

    @JsonProperty("affectedComponentCount")
    public Integer getAffectedComponentCount() {
        return affectedComponentCount;
    }

    @JsonProperty("affectedComponentCount")
    public void setAffectedComponentCount(Integer affectedComponentCount) {
        this.affectedComponentCount = affectedComponentCount;
    }

    @JsonProperty("criticalComponentCount")
    public Integer getCriticalComponentCount() {
        return criticalComponentCount;
    }

    @JsonProperty("criticalComponentCount")
    public void setCriticalComponentCount(Integer criticalComponentCount) {
        this.criticalComponentCount = criticalComponentCount;
    }

    @JsonProperty("severeComponentCount")
    public Integer getSevereComponentCount() {
        return severeComponentCount;
    }

    @JsonProperty("severeComponentCount")
    public void setSevereComponentCount(Integer severeComponentCount) {
        this.severeComponentCount = severeComponentCount;
    }

    @JsonProperty("moderateComponentCount")
    public Integer getModerateComponentCount() {
        return moderateComponentCount;
    }

    @JsonProperty("moderateComponentCount")
    public void setModerateComponentCount(Integer moderateComponentCount) {
        this.moderateComponentCount = moderateComponentCount;
    }

    @JsonProperty("criticalPolicyViolationCount")
    public Integer getCriticalPolicyViolationCount() {
        return criticalPolicyViolationCount;
    }

    @JsonProperty("criticalPolicyViolationCount")
    public void setCriticalPolicyViolationCount(Integer criticalPolicyViolationCount) {
        this.criticalPolicyViolationCount = criticalPolicyViolationCount;
    }

    @JsonProperty("severePolicyViolationCount")
    public Integer getSeverePolicyViolationCount() {
        return severePolicyViolationCount;
    }

    @JsonProperty("severePolicyViolationCount")
    public void setSeverePolicyViolationCount(Integer severePolicyViolationCount) {
        this.severePolicyViolationCount = severePolicyViolationCount;
    }

    @JsonProperty("moderatePolicyViolationCount")
    public Integer getModeratePolicyViolationCount() {
        return moderatePolicyViolationCount;
    }

    @JsonProperty("moderatePolicyViolationCount")
    public void setModeratePolicyViolationCount(Integer moderatePolicyViolationCount) {
        this.moderatePolicyViolationCount = moderatePolicyViolationCount;
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
