
package com.sonatype.ssc.intsvc.iq.scanhistory;

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
    "stage",
    "applicationId",
    "evaluationDate",
    "latestReportHtmlUrl",
    "reportHtmlUrl",
    "embeddableReportHtmlUrl",
    "reportPdfUrl",
    "reportDataUrl",
    "policyEvaluationId",
    "scanId",
    "isReevaluation",
    "isForMonitoring",
    "commitHash",
    "policyEvaluationResult"
})
public class Report {

    @JsonProperty("stage")
    private String stage;
    @JsonProperty("applicationId")
    private String applicationId;
    @JsonProperty("evaluationDate")
    private String evaluationDate;
    @JsonProperty("latestReportHtmlUrl")
    private String latestReportHtmlUrl;
    @JsonProperty("reportHtmlUrl")
    private String reportHtmlUrl;
    @JsonProperty("embeddableReportHtmlUrl")
    private String embeddableReportHtmlUrl;
    @JsonProperty("reportPdfUrl")
    private String reportPdfUrl;
    @JsonProperty("reportDataUrl")
    private String reportDataUrl;
    @JsonProperty("policyEvaluationId")
    private String policyEvaluationId;
    @JsonProperty("scanId")
    private String scanId;
    @JsonProperty("isReevaluation")
    private Boolean isReevaluation;
    @JsonProperty("isForMonitoring")
    private Boolean isForMonitoring;
    @JsonProperty("commitHash")
    private Object commitHash;
    @JsonProperty("policyEvaluationResult")
    private PolicyEvaluationResult policyEvaluationResult;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("stage")
    public String getStage() {
        return stage;
    }

    @JsonProperty("stage")
    public void setStage(String stage) {
        this.stage = stage;
    }

    @JsonProperty("applicationId")
    public String getApplicationId() {
        return applicationId;
    }

    @JsonProperty("applicationId")
    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    @JsonProperty("evaluationDate")
    public String getEvaluationDate() {
        return evaluationDate;
    }

    @JsonProperty("evaluationDate")
    public void setEvaluationDate(String evaluationDate) {
        this.evaluationDate = evaluationDate;
    }

    @JsonProperty("latestReportHtmlUrl")
    public String getLatestReportHtmlUrl() {
        return latestReportHtmlUrl;
    }

    @JsonProperty("latestReportHtmlUrl")
    public void setLatestReportHtmlUrl(String latestReportHtmlUrl) {
        this.latestReportHtmlUrl = latestReportHtmlUrl;
    }

    @JsonProperty("reportHtmlUrl")
    public String getReportHtmlUrl() {
        return reportHtmlUrl;
    }

    @JsonProperty("reportHtmlUrl")
    public void setReportHtmlUrl(String reportHtmlUrl) {
        this.reportHtmlUrl = reportHtmlUrl;
    }

    @JsonProperty("embeddableReportHtmlUrl")
    public String getEmbeddableReportHtmlUrl() {
        return embeddableReportHtmlUrl;
    }

    @JsonProperty("embeddableReportHtmlUrl")
    public void setEmbeddableReportHtmlUrl(String embeddableReportHtmlUrl) {
        this.embeddableReportHtmlUrl = embeddableReportHtmlUrl;
    }

    @JsonProperty("reportPdfUrl")
    public String getReportPdfUrl() {
        return reportPdfUrl;
    }

    @JsonProperty("reportPdfUrl")
    public void setReportPdfUrl(String reportPdfUrl) {
        this.reportPdfUrl = reportPdfUrl;
    }

    @JsonProperty("reportDataUrl")
    public String getReportDataUrl() {
        return reportDataUrl;
    }

    @JsonProperty("reportDataUrl")
    public void setReportDataUrl(String reportDataUrl) {
        this.reportDataUrl = reportDataUrl;
    }

    @JsonProperty("policyEvaluationId")
    public String getPolicyEvaluationId() {
        return policyEvaluationId;
    }

    @JsonProperty("policyEvaluationId")
    public void setPolicyEvaluationId(String policyEvaluationId) {
        this.policyEvaluationId = policyEvaluationId;
    }

    @JsonProperty("scanId")
    public String getScanId() {
        return scanId;
    }

    @JsonProperty("scanId")
    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    @JsonProperty("isReevaluation")
    public Boolean getIsReevaluation() {
        return isReevaluation;
    }

    @JsonProperty("isReevaluation")
    public void setIsReevaluation(Boolean isReevaluation) {
        this.isReevaluation = isReevaluation;
    }

    @JsonProperty("isForMonitoring")
    public Boolean getIsForMonitoring() {
        return isForMonitoring;
    }

    @JsonProperty("isForMonitoring")
    public void setIsForMonitoring(Boolean isForMonitoring) {
        this.isForMonitoring = isForMonitoring;
    }

    @JsonProperty("commitHash")
    public Object getCommitHash() {
        return commitHash;
    }

    @JsonProperty("commitHash")
    public void setCommitHash(Object commitHash) {
        this.commitHash = commitHash;
    }

    @JsonProperty("policyEvaluationResult")
    public PolicyEvaluationResult getPolicyEvaluationResult() {
        return policyEvaluationResult;
    }

    @JsonProperty("policyEvaluationResult")
    public void setPolicyEvaluationResult(PolicyEvaluationResult policyEvaluationResult) {
        this.policyEvaluationResult = policyEvaluationResult;
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
