package com.sonatype.ssc.model;

/**
 * (c) Copyright Sonatype Inc. 2018
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.math.BigDecimal;

@JsonSerialize
public class Finding {
  // GenPriority should exactly copy values from
  // com.fortify.plugin.api.BasicVulnerabilityBuilder.Priority
  // We don't use the original Priority here because we don't want model to be
  // dependent on the SSC plugin-api
  public enum Priority {
    Critical, High, Medium, Low;

    public static final int LENGTH = values().length;
  }

  public enum CustomStatus {
    NEW, OPEN, REMEDIATED;

    public static final int LENGTH = values().length;
  }

  // mandatory attributes
  private String uniqueId;

  // built-in attributes
  private String category;
  private String fileName;
  private String vulnerabilityAbstract;
  private Integer lineNumber;
  private Float confidence;
  private Float impact;
  private Priority priority;

  // custom attributes
  private String categoryId;
  private String artifact;
  private String description;
  private String comment;
  private CustomStatus customStatus;
  private String reportUrl;
  private String issue;
  private String source;
  private String cweurl;
  private String cveurl;
  private String group;
  private String version;

  private String recommendedVersion;

  //private String identificationSource;
  //private String website;
  //private String cataloged;
  //private String matchState;
  //private String effectiveLicense;
  private String sonatypeThreatLevel;

  public String getRecommendedVersion() {
    return recommendedVersion;
  }

  public void setRecommendedVersion(String recommendedVersion) {
    this.recommendedVersion = recommendedVersion;
  }

  /*public String getIdentificationSource() {
    return identificationSource;
  }

  public void setIdentificationSource(String identificationSource) {
    this.identificationSource = identificationSource;
  }*/

  /*public String getWebsite() {
    return website;
  }

  public void setWebsite(String website) {
    this.website = website;
  }*/

  /*public String getCataloged() {
    return cataloged;
  }

  public void setCataloged(String cataloged) {
    this.cataloged = cataloged;
  }*/

  /*public String getMatchState() {
    return matchState;
  }

  public void setMatchState(String matchState) {
    this.matchState = matchState;
  }*/

  public String getVersion() {
    return version;
  }

  public void setVersion(String version) {
    this.version = version;
  }

  /*public String getEffectiveLicense() {
    return effectiveLicense;
  }

  public void setEffectiveLicense(String effectiveLicense) {
    this.effectiveLicense = effectiveLicense;
  }*/

  public String getGroup() {
    return group;
  }

  public void setGroup(String group) {
    this.group = group;
  }

  public String getCweurl() {
    return cweurl;
  }

  public void setCweurl(String cweurl) {
    this.cweurl = cweurl;
  }

  public String getSonatypeThreatLevel() {
    return sonatypeThreatLevel;
  }

  public void setSonatypeThreatLevel(String sonatypeThreatLevel) {
    this.sonatypeThreatLevel = sonatypeThreatLevel;
  }

  public String getCveurl() {
    return cveurl;
  }

  public void setCveurl(String cveurl) {
    this.cveurl = cveurl;
  }

  private BigDecimal cwecwe;

  public BigDecimal getCwecwe() {
    return cwecwe;
  }

  public void setCwecwe(BigDecimal cwecwe) {
    this.cwecwe = cwecwe;
  }

  private BigDecimal cvecvss3;

  public BigDecimal getCvecvss3() {
    return cvecvss3;
  }

  public void setCvecvss3(BigDecimal cvecvss3) {
    this.cvecvss3 = cvecvss3;
  }

  // sonatypecvss3
  private BigDecimal sonatypecvss3;

  public BigDecimal getSonatypecvss3() {
    return sonatypecvss3;
  }

  public void setSonatypecvss3(BigDecimal sonatypecvss3) {
    this.sonatypecvss3 = sonatypecvss3;
  }

  private BigDecimal cvecvss2;

  public BigDecimal getCvecvss2() {
    return cvecvss2;
  }

  public void setCvecvss2(BigDecimal cvecvss2) {
    this.cvecvss2 = cvecvss2;
  }

  public String getSource() {
    return source;
  }

  public void setSource(String source) {
    this.source = source;
  }

  public String getIssue() {
    return issue;
  }

  public void setIssue(String issue) {
    this.issue = issue;
  }

  public String getReportUrl() {
    return reportUrl;
  }

  public void setReportUrl(String reportUrl) {
    this.reportUrl = reportUrl;
  }

  public String getUniqueId() {
    return uniqueId;
  }

  public String getCategory() {
    return category;
  }

  public void setCategory(final String category) {
    this.category = category;
  }

  public String getFileName() {
    return fileName;
  }

  public void setFileName(final String fileName) {
    this.fileName = fileName;
  }

  public String getVulnerabilityAbstract() {
    return vulnerabilityAbstract;
  }

  public void setVulnerabilityAbstract(final String vulnerabilityAbstract) {
    this.vulnerabilityAbstract = vulnerabilityAbstract;
  }

  public Integer getLineNumber() {
    return lineNumber;
  }

  public void setLineNumber(final Integer lineNumber) {
    this.lineNumber = lineNumber;
  }

  public Float getConfidence() {
    return confidence;
  }

  public void setConfidence(final Float confidence) {
    this.confidence = confidence;
  }

  public Float getImpact() {
    return impact;
  }

  public void setImpact(final Float impact) {
    this.impact = impact;
  }

  public void setUniqueId(final String uniqueId) {
    this.uniqueId = uniqueId;
  }

  public Priority getPriority() {
    return priority;
  }

  public void setPriority(final Priority priority) {
    this.priority = priority;
  }

  public String getCategoryId() {
    return categoryId;
  }

  public void setCategoryId(final String categoryId) {
    this.categoryId = categoryId;
  }

  public String getArtifact() {
    return artifact;
  }

  public void setArtifact(final String artifact) {
    this.artifact = artifact;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(final String description) {
    this.description = description;
  }

  public String getComment() {
    return comment;
  }

  public void setComment(final String comment) {
    this.comment = comment;
  }

  public CustomStatus getCustomStatus() {
    return customStatus;
  }

  public void setCustomStatus(final CustomStatus customStatus) {
    this.customStatus = customStatus;
  }
}
