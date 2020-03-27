
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
    "packageUrl",
    "hash",
    "componentIdentifier"
})
public class Component {

    @JsonProperty("packageUrl")
    private String packageUrl;
    @JsonProperty("hash")
    private Object hash;
    @JsonProperty("componentIdentifier")
    private ComponentIdentifier componentIdentifier;
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
    public Object getHash() {
        return hash;
    }

    @JsonProperty("hash")
    public void setHash(Object hash) {
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
        return new ToStringBuilder(this).append("packageUrl", packageUrl).append("hash", hash).append("componentIdentifier", componentIdentifier).append("additionalProperties", additionalProperties).toString();
    }

}
