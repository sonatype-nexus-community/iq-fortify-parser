
package com.sonatype.ssc.intsvc.model.PolicyViolation;

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
    "constraintId",
    "constraintName",
    "conditions"
})
public class Constraint {

    @JsonProperty("constraintId")
    private String constraintId;
    @JsonProperty("constraintName")
    private String constraintName;
    @JsonProperty("conditions")
    private List<Condition> conditions = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("constraintId")
    public String getConstraintId() {
        return constraintId;
    }

    @JsonProperty("constraintId")
    public void setConstraintId(String constraintId) {
        this.constraintId = constraintId;
    }

    @JsonProperty("constraintName")
    public String getConstraintName() {
        return constraintName;
    }

    @JsonProperty("constraintName")
    public void setConstraintName(String constraintName) {
        this.constraintName = constraintName;
    }

    @JsonProperty("conditions")
    public List<Condition> getConditions() {
        return conditions;
    }

    @JsonProperty("conditions")
    public void setConditions(List<Condition> conditions) {
        this.conditions = conditions;
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
