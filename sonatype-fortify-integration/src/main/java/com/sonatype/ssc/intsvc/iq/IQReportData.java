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
package com.sonatype.ssc.intsvc.iq;

/*
    {
        "stage": "build",
        "applicationId": "4537e6fe68c24dd5ac83efd97d4fc2f4",
        "evaluationDate": "2015-01-16T13:14:32.139-05:00",
        "latestReportHtmlUrl": "ui/links/application/Test123/latestReport/build",
        "reportHtmlUrl": "ui/links/application/Test123/report/474ca07881554f8fbec168ec25d9616a",
        "embeddableReportHtmlUrl": "ui/links/application/Test123/report/474ca07881554f8fbec168ec25d9616a/embeddable",
        "reportPdfUrl": "ui/links/application/Test123/report/474ca07881554f8fbec168ec25d9616a/pdf",
        "reportDataUrl": "api/v2/applications/Test123/reports/474ca07881554f8fbec168ec25d9616a"
    },
 */

/**
 * see https://help.sonatype.com/iqserver/automating/rest-apis/report-related-rest-apis---v2#Report-relatedRESTAPIs-v2-reportId
 */
public class IQReportData
{
  private String stage;
  private String applicationId;
  private String evaluationDate;
  private String latestReportHtmlUrl;
  private String reportHtmlUrl;
  private String embeddableReportHtmlUrl;
  private String reportPdfUrl;
  private String reportDataUrl;

  public String getReportId() {
    return reportHtmlUrl.substring(reportHtmlUrl.indexOf("/report/") + 8, reportHtmlUrl.length());
  }

  private transient String reportUrl; // not part of IQ REST API, but useful to the integration

  public String getReportUrl() {
    return reportUrl;
  }

  public void setReportUrl(String reportUrl) {
    this.reportUrl = reportUrl;
  }

  @Override
  public String toString()
  {
    return "IQReportData [applicationId = " + applicationId + ", stage = " + stage + "]";
  }

  public String getStage() {
    return stage;
  }

  public void setStage(String stage) {
    this.stage = stage;
  }

  public String getApplicationId() {
    return applicationId;
  }

  public void setApplicationId(String applicationId) {
    this.applicationId = applicationId;
  }

  public String getEvaluationDate() {
    return evaluationDate;
  }

  public void setEvaluationDate(String evaluationDate) {
    this.evaluationDate = evaluationDate;
  }

  public String getLatestReportHtmlUrl() {
    return latestReportHtmlUrl;
  }

  public void setLatestReportHtmlUrl(String latestReportHtmlUrl) {
    this.latestReportHtmlUrl = latestReportHtmlUrl;
  }

  public String getReportHtmlUrl() {
    return reportHtmlUrl;
  }

  public void setReportHtmlUrl(String reportHtmlUrl) {
    this.reportHtmlUrl = reportHtmlUrl;
  }

  public String getEmbeddableReportHtmlUrl() {
    return embeddableReportHtmlUrl;
  }

  public void setEmbeddableReportHtmlUrl(String embeddableReportHtmlUrl) {
    this.embeddableReportHtmlUrl = embeddableReportHtmlUrl;
  }

  public String getReportPdfUrl() {
    return reportPdfUrl;
  }

  public void setReportPdfUrl(String reportPdfUrl) {
    this.reportPdfUrl = reportPdfUrl;
  }

  public String getReportDataUrl() {
    return reportDataUrl;
  }

  public void setReportDataUrl(String reportDataUrl) {
    this.reportDataUrl = reportDataUrl;
  }
}
