/*
 * Copyright (c) 2016-present Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.sonatype.ssc.intsvc.model;

import com.sonatype.ssc.intsvc.model.Remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.VulnDetailResponse;

/**
 * Sonatype vulnerability as it will be loaded to SSC as a list tied to a scan.
 */
public class SonatypeVuln
{
  private String uniqueId;

  public String getUniqueId() {
    return uniqueId;
  }

  public void setUniqueId(String uniqueId) {
    if (uniqueId != null) {
      this.uniqueId = uniqueId;
    }
    else {
      this.uniqueId = "";
    }
  }

  public VulnDetailResponse getVulnDetail() {
    return vulnDetail;
  }

  public void setVulnDetail(VulnDetailResponse vulnDetail) {
    this.vulnDetail = vulnDetail;
  }

  private VulnDetailResponse vulnDetail;

  private String issue;

  public String getIssue() {
    return issue;
  }

  public void setIssue(String issue) {
    if (issue != null) {
      this.issue = issue;
    }
    else {
      this.issue = "";
    }
  }

  private String cweurl;

  public String getCweurl() {
    return cweurl;
  }

  public void setCweurl(String cweurl) {
    if (cweurl != null) {
      this.cweurl = cweurl;
    }
    else {
      this.cweurl = "";
    }
  }

  private String cveurl;

  public String getCveurl() {
    return cveurl;
  }

  public void setCveurl(String cveurl) {
    if (cveurl != null) {
      this.cveurl = cveurl;
    }
    else {
      this.cveurl = "";
    }
  }

  private String source;

  public String getSource() {
    return source;
  }

  public void setSource(String source) {
    if (source != null) {
      this.source = source;
    }
    else {
      this.source = "";
    }
  }

  private String sonatypeThreatLevel;

  public String getSonatypeThreatLevel() {
    return sonatypeThreatLevel;
  }

  public void setSonatypeThreatLevel(String sonatypeThreatLevel) {
    if (sonatypeThreatLevel != null) {
      this.sonatypeThreatLevel = sonatypeThreatLevel;
    }
    else {
      this.sonatypeThreatLevel = "";
    }
  }

  private String cvecvss3;

  public String getCvecvss3() {
    return cvecvss3;
  }

  public void setCvecvss3(String cvecvss3) {
    if (cvecvss3 != null) {
      this.cvecvss3 = cvecvss3;
    }
    else {
      this.cvecvss3 = "";
    }
  }

  private String group;

  public String getGroup() {
    return group;
  }

  public void setGroup(String group) {
    if (group != null) {
      this.group = group;
    }
    else {
      this.group = "";
    }
  }

  private String artifact;

  public String getArtifact() {
    return artifact;
  }

  public void setArtifact(String artifact) {
    if (artifact != null) {
      this.artifact = artifact;
    }
    else {
      this.artifact = "";
    }
  }

  private String version;

  public String getVersion() {
    return version;
  }

  public void setVersion(String version) {
    if (version != null) {
      this.version = version;
    }
    else {
      this.version = "";
    }
  }

  private String extension;

  public String getExtension() {
    return extension;
  }

  public void setExtension(String extension) {
    if (extension != null) {
      this.extension = extension;
    }
    else {
      this.extension = "";
    }
  }

  private String format;

  public String getFormat() {
    return format;
  }

  public void setFormat(String format) {
    if (format != null) {
      this.format = format;
    }
    else {
      this.format = "";
    }
  }

  private String priority;

  public String getPriority() {
    return priority;
  }

  public void setPriority(String priority) {
    if (priority != null) {
      this.priority = priority;
    }
    else {
      this.priority = "";
    }
  }

  private String effectiveLicense;

  public String getEffectiveLicense() {
    return effectiveLicense;
  }

  public void setEffectiveLicense(String effectiveLicense) {
    if (effectiveLicense != null) {
      this.effectiveLicense = effectiveLicense;
    }
    else {
      this.effectiveLicense = "";
    }
  }

  private String fileName;

  public String getFileName() {
    return fileName;
  }

  public void setFileName(String fileName) {
    if (fileName != null) {
      this.fileName = fileName;
    }
    else {
      this.fileName = "";
    }
  }

  private String name;

  public String getName() {
    return name;
  }

  public void setName(String name) {
    if (name != null) {
      this.name = name;
    }
    else {
      this.name = "";
    }
  }

  private String qualifier;

  public String getQualifier() {
    return qualifier;
  }

  public void setQualifier(String qualifier) {
    if (qualifier != null) {
      this.qualifier = qualifier;
    }
    else {
      this.qualifier = "";
    }
  }

//  private String htmlDetails;
//
//  public String getHtmlDetails() {
//    return htmlDetails;
//  }
//
//  public void setHtmlDetails(String htmlDetails) {
//    if (htmlDetails != null) {
//      this.htmlDetails = htmlDetails;
//    }
//    else {
//      this.htmlDetails = "";
//    }
//  }

  private String compReportDetails;

  public String getCompReportDetails() {
    return compReportDetails;
  }

  public void setCompReportDetails(String compReportDetails) {
    if (compReportDetails != null) {
      this.compReportDetails = compReportDetails;
    }
    else {
      this.compReportDetails = "";
    }
  }

  private String vulnDetailsJson;

  public String getVulnDetailsJson() {
    return vulnDetailsJson;
  }

  public void setVulnDetailsJson(String vulnDetailsJson) {
    if (vulnDetailsJson != null) {
      this.vulnDetailsJson = vulnDetailsJson;
    }
    else {
      this.vulnDetailsJson = "";
    }
  }

  public RemediationResponse getRemediationResponse() {
    return remediationResponse;
  }

  public void setRemediationResponse(RemediationResponse remediationResponse) {
    this.remediationResponse = remediationResponse;
  }

  private RemediationResponse remediationResponse;

  private String hash;

  public String getHash() {
    return hash;
  }

  public void setHash(String hash) {
    if (hash != null) {
      this.hash = hash;
    }
    else {
      this.hash = "";
    }
  }

  private String compReportURL;

  public String getCompReportURL() {
    return compReportURL;
  }

  public void setCompReportURL(String compReportURL) {
    if (compReportURL != null) {
      this.compReportURL = compReportURL;
    }
    else {
      this.compReportURL = "";
    }
  }

  private String reportUrl;

  public String getReportUrl() {
    return reportUrl;
  }

  public void setReportUrl(String reportUrl) {
    this.reportUrl = reportUrl;
  }
}
