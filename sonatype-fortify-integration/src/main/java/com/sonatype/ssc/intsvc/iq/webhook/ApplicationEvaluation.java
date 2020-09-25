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
package com.sonatype.ssc.intsvc.iq.webhook;

/*
    "applicationEvaluation": {
        "application": {
            "id": "0e07cbca0b6a4061a4d7dd92b402b9e1",
            "publicId": "accents",
            "name": "Accents",
            "organizationId": "51ee28cc089b4373af00c3ea2d522a32"
        },
        "policyEvaluationId": "1ccfd7a041a249648cb8195836cece73",
        "stage": "build",
        "ownerId": "0e07cbca0b6a4061a4d7dd92b402b9e1",
        "evaluationDate": "2020-09-24T14:15:12.120+0000",
        "affectedComponentCount": 0,
        "criticalComponentCount": 0,
        "severeComponentCount": 0,
        "moderateComponentCount": 0,
        "outcome": "none",
        "reportId": "c640ea664bcb41e7bacd9ff6e39a3cd9",
        "isForLatestScan": true
    }
}
*/
public class ApplicationEvaluation {
  private Application application;
  private String policyEvaluationId;
  private String stage;
  private String evaluationDate;
  private int affectedComponentCount;
  private int criticalComponentCount;
  private int severeComponentCount;
  private int moderateComponentCount;
  private String outcome;
  private String reportId;
  private boolean isForLatestScan;

  public static class Application {
    private String id;
    private String publicId;
    private String name;
    private String organizationId;

    public String getId() {
      return id;
    }

    public void setId(String id) {
      this.id = id;
    }

    public String getPublicId() {
      return publicId;
    }

    public void setPublicId(String publicId) {
      this.publicId = publicId;
    }

    public String getName() {
      return name;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getOrganizationId() {
      return organizationId;
    }

    public void setOrganizationId(String organizationId) {
      this.organizationId = organizationId;
    }
  }

  public Application getApplication() {
    return application;
  }

  public void setApplication(Application application) {
    this.application = application;
  }

  public String getPolicyEvaluationId() {
    return policyEvaluationId;
  }

  public void setPolicyEvaluationId(String policyEvaluationId) {
    this.policyEvaluationId = policyEvaluationId;
  }

  public String getStage() {
    return stage;
  }

  public void setStage(String stage) {
    this.stage = stage;
  }

  public String getEvaluationDate() {
    return evaluationDate;
  }

  public void setEvaluationDate(String evaluationDate) {
    this.evaluationDate = evaluationDate;
  }

  public int getAffectedComponentCount() {
    return affectedComponentCount;
  }

  public void setAffectedComponentCount(int affectedComponentCount) {
    this.affectedComponentCount = affectedComponentCount;
  }

  public int getCriticalComponentCount() {
    return criticalComponentCount;
  }

  public void setCriticalComponentCount(int criticalComponentCount) {
    this.criticalComponentCount = criticalComponentCount;
  }

  public int getSevereComponentCount() {
    return severeComponentCount;
  }

  public void setSevereComponentCount(int severeComponentCount) {
    this.severeComponentCount = severeComponentCount;
  }

  public int getModerateComponentCount() {
    return moderateComponentCount;
  }

  public void setModerateComponentCount(int moderateComponentCount) {
    this.moderateComponentCount = moderateComponentCount;
  }

  public String getOutcome() {
    return outcome;
  }

  public void setOutcome(String outcome) {
    this.outcome = outcome;
  }

  public String getReportId() {
    return reportId;
  }

  public void setReportId(String reportId) {
    this.reportId = reportId;
  }

  public boolean isForLatestScan() {
    return isForLatestScan;
  }

  public void setForLatestScan(boolean isForLatestScan) {
    this.isForLatestScan = isForLatestScan;
  }
}
