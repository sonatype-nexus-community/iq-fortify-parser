
package com.sonatype.ssc.integration.fortify.model.Remediation;

import java.util.HashMap;
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
    "artifactId",
    "classifier",
    "extension",
    "groupId",
    "version"
})
public class Coordinates {

    @JsonProperty("artifactId")
    private String artifactId;
    @JsonProperty("classifier")
    private String classifier;
    @JsonProperty("extension")
    private String extension;
    @JsonProperty("groupId")
    private String groupId;
    @JsonProperty("version")
    private String version;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("artifactId")
    public String getArtifactId() {
        return artifactId;
    }

    @JsonProperty("artifactId")
    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    @JsonProperty("classifier")
    public String getClassifier() {
        return classifier;
    }

    @JsonProperty("classifier")
    public void setClassifier(String classifier) {
        this.classifier = classifier;
    }

    @JsonProperty("extension")
    public String getExtension() {
        return extension;
    }

    @JsonProperty("extension")
    public void setExtension(String extension) {
        this.extension = extension;
    }

    @JsonProperty("groupId")
    public String getGroupId() {
        return groupId;
    }

    @JsonProperty("groupId")
    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    @JsonProperty("version")
    public String getVersion() {
        return version;
    }

    @JsonProperty("version")
    public void setVersion(String version) {
        this.version = version;
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
        return new ToStringBuilder(this).append("artifactId", artifactId).append("classifier", classifier).append("extension", extension).append("groupId", groupId).append("version", version).append("additionalProperties", additionalProperties).toString();
    }

}
