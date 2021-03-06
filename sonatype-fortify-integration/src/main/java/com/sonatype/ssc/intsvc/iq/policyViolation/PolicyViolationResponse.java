
package com.sonatype.ssc.intsvc.iq.policyViolation;

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
    "reportTime",
    "reportTitle",
    "commitHash",
    "initiator",
    "application",
    "counts",
    "components"
})
public class PolicyViolationResponse {

    @JsonProperty("reportTime")
    private long reportTime;
    @JsonProperty("reportTitle")
    private String reportTitle;
    @JsonProperty("commitHash")
    private String commitHash; // since IQ release 92
    @JsonProperty("initiator")
    private String initiator; // since IQ release 98
    @JsonProperty("application")
    private Application application;
    @JsonProperty("counts")
    private Counts counts;
    @JsonProperty("components")
    private List<Component> components = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("reportTime")
    public long getReportTime() {
        return reportTime;
    }

    @JsonProperty("reportTime")
    public void setReportTime(long reportTime) {
        this.reportTime = reportTime;
    }

    @JsonProperty("reportTitle")
    public String getReportTitle() {
        return reportTitle;
    }

    @JsonProperty("reportTitle")
    public void setReportTitle(String reportTitle) {
        this.reportTitle = reportTitle;
    }

    @JsonProperty("commitHash")
    public String getCommitHash() {
        return commitHash;
    }

    @JsonProperty("commitHash")
    public void setCommitHash(String commitHash) {
        this.commitHash = commitHash;
    }

    @JsonProperty("initiator")
    public String getInitiator() {
        return initiator;
    }

    @JsonProperty("initiator")
    public void setInitiator(String initiator) {
        this.initiator = initiator;
    }

    @JsonProperty("application")
    public Application getApplication() {
        return application;
    }

    @JsonProperty("application")
    public void setApplication(Application application) {
        this.application = application;
    }

    @JsonProperty("counts")
    public Counts getCounts() {
        return counts;
    }

    @JsonProperty("counts")
    public void setCounts(Counts counts) {
        this.counts = counts;
    }

    @JsonProperty("components")
    public List<Component> getComponents() {
        return components;
    }

    @JsonProperty("components")
    public void setComponents(List<Component> components) {
        this.components = components;
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
