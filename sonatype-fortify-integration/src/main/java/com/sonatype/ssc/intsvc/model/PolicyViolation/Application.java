
package com.sonatype.ssc.intsvc.model.PolicyViolation;

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
    "id",
    "publicId",
    "name",
    "organizationId",
    "contactUserName"
})
public class Application {

    @JsonProperty("id")
    private String id;
    @JsonProperty("publicId")
    private String publicId;
    @JsonProperty("name")
    private String name;
    @JsonProperty("organizationId")
    private String organizationId;
    @JsonProperty("contactUserName")
    private Object contactUserName;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("publicId")
    public String getPublicId() {
        return publicId;
    }

    @JsonProperty("publicId")
    public void setPublicId(String publicId) {
        this.publicId = publicId;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("organizationId")
    public String getOrganizationId() {
        return organizationId;
    }

    @JsonProperty("organizationId")
    public void setOrganizationId(String organizationId) {
        this.organizationId = organizationId;
    }

    @JsonProperty("contactUserName")
    public Object getContactUserName() {
        return contactUserName;
    }

    @JsonProperty("contactUserName")
    public void setContactUserName(Object contactUserName) {
        this.contactUserName = contactUserName;
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
