
package com.sonatype.ssc.intsvc.model.Remediation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import org.apache.commons.lang3.builder.ToStringBuilder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "versionChanges"
})
public class Remediation {

    @JsonProperty("versionChanges")
    private List<VersionChange> versionChanges = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("versionChanges")
    public List<VersionChange> getVersionChanges() {
        return versionChanges;
    }

    @JsonProperty("versionChanges")
    public void setVersionChanges(List<VersionChange> versionChanges) {
        this.versionChanges = versionChanges;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this).append("versionChanges", versionChanges).append("additionalProperties", additionalProperties).toString();
    }

}
