
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
    "packageUrl",
    "hash",
    "componentIdentifier",
    "proprietary",
    "matchState",
    "pathnames",
    "violations"
})
public class Component {

    @JsonProperty("packageUrl")
    private String packageUrl;
    @JsonProperty("hash")
    private String hash;
    @JsonProperty("componentIdentifier")
    private ComponentIdentifier componentIdentifier;
    @JsonProperty("proprietary")
    private Boolean proprietary;
    @JsonProperty("matchState")
    private String matchState;
    @JsonProperty("pathnames")
    private List<String> pathnames = null;
    @JsonProperty("violations")
    private List<Violation> violations = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("packageUrl")
    public String getPackageUrl() {
        return packageUrl;
    }

    @JsonProperty("packageUrl")
    public void setPackageUrl(String packageUrl) {
        this.packageUrl = packageUrl;
    }

    @JsonProperty("hash")
    public String getHash() {
        return hash;
    }

    @JsonProperty("hash")
    public void setHash(String hash) {
        this.hash = hash;
    }

    @JsonProperty("componentIdentifier")
    public ComponentIdentifier getComponentIdentifier() {
        return componentIdentifier;
    }

    @JsonProperty("componentIdentifier")
    public void setComponentIdentifier(ComponentIdentifier componentIdentifier) {
        this.componentIdentifier = componentIdentifier;
    }

    @JsonProperty("proprietary")
    public Boolean getProprietary() {
        return proprietary;
    }

    @JsonProperty("proprietary")
    public void setProprietary(Boolean proprietary) {
        this.proprietary = proprietary;
    }

    @JsonProperty("matchState")
    public String getMatchState() {
        return matchState;
    }

    @JsonProperty("matchState")
    public void setMatchState(String matchState) {
        this.matchState = matchState;
    }

    @JsonProperty("pathnames")
    public List<String> getPathnames() {
        return pathnames;
    }

    @JsonProperty("pathnames")
    public void setPathnames(List<String> pathnames) {
        this.pathnames = pathnames;
    }

    @JsonProperty("violations")
    public List<Violation> getViolations() {
        return violations;
    }

    @JsonProperty("violations")
    public void setViolations(List<Violation> violations) {
        this.violations = violations;
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
