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
package com.sonatype.ssc.integration.fortify.model;

public class IQProjectData
{

  private String projectName;

  public String getProjectName() {
    return projectName;
  }

  public void setProjectName(String projectName) {
    if (projectName != null) {
      this.projectName = projectName;
    }
    else {
      this.projectName = "";
    }
  }

  private String projectPublicId;

  public String getProjectPublicId() {
    return projectPublicId;
  }

  public void setProjectPublicId(String projectPublicId) {
    if (projectPublicId != null) {
      this.projectPublicId = projectPublicId;
    }
    else {
      this.projectPublicId = "";
    }
  }

  private String projectStage;

  public String getProjectStage() {
    return projectStage;
  }

  public void setProjectStage(String projectStage) {
    if (projectStage != null) {
      this.projectStage = projectStage;
    }
    else {
      this.projectStage = "";
    }
  }

  private String internalAppId;

  public String getInternalAppId() {
    return internalAppId;
  }

  public void setInternalAppId(String internalAppId) {
    if (internalAppId != null) {
      this.internalAppId = internalAppId;
    }
    else {
      this.internalAppId = "";
    }
  }

  private String projectIQReportURL;

  public String getProjectIQReportURL() {
    return this.projectIQReportURL;
  }

  public void setProjectIQReportURL(String projectIQReportURL) {
    this.projectIQReportURL = (projectIQReportURL != null) ? projectIQReportURL : "";
  }

  private String projectReportURL;

  public String getProjectReportURL() {
    return projectReportURL;
  }

  public void setProjectReportURL(String projectReportURL) {
    if (projectReportURL != null) {
      this.projectReportURL = projectReportURL;
    }
    else {
      this.projectReportURL = "";
    }
  }

  private String projectReportId;

  public String getProjectReportId() {
    return projectReportId;
  }

  public void setProjectReportId(String projectReportId) {
    if (projectReportId != null) {
      this.projectReportId = projectReportId;
    }
    else {
      this.projectReportId = "";
    }
  }

  private String evaluationDate;

  public String getEvaluationDate() {
    return evaluationDate;
  }

  public void setEvaluationDate(String evaluationDate) {
    if (evaluationDate != null) {
      this.evaluationDate = evaluationDate;
    }
    else {
      this.evaluationDate = "";
    }
  }
}
