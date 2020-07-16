/*
 * Copyright (c) 2020-present Sonatype, Inc. All rights reserved.
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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class IQSSCMapping {
  private String iqProject;
  private String iqProjectStage;
  private String sscApplication;
  private String sscApplicationVersion;

  public IQSSCMapping() {
  }

  public IQSSCMapping(String iqProject, String iqProjectStage, String sscApplication, String sscApplicationVersion) {
    this.iqProject = iqProject;
    this.iqProjectStage = iqProjectStage;
    this.sscApplication = sscApplication;
    this.sscApplicationVersion = sscApplicationVersion;
  }

  public String getIqProject() {
    return iqProject;
  }

  public void setIqProject(String iqProject) {
    this.iqProject = iqProject;
  }

  public String getIqProjectStage() {
    return iqProjectStage;
  }

  public void setIqProjectStage(String iqProjectStage) {
    this.iqProjectStage = iqProjectStage;
  }

  public String getSscApplication() {
    return sscApplication;
  }

  public void setSscApplication(String sscApplication) {
    this.sscApplication = sscApplication;
  }

  public String getSscApplicationVersion() {
    return sscApplicationVersion;
  }

  public void setSscApplicationVersion(String sscApplicationVersion) {
    this.sscApplicationVersion = sscApplicationVersion;
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder().append(iqProject).append(iqProjectStage).append(sscApplication)
        .append(sscApplicationVersion).toHashCode();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj instanceof IQSSCMapping) {
      IQSSCMapping other = (IQSSCMapping) obj;
      return StringUtils.equals(iqProject, other.iqProject) && StringUtils.equals(iqProjectStage, other.iqProjectStage)
          && StringUtils.equals(sscApplication, other.sscApplication)
          && StringUtils.equals(sscApplicationVersion, other.sscApplicationVersion);
    }
    return false;
  }

  public String toJson() {
    return "{" + System.lineSeparator() +
        "\"sonatypeProject\": \"" + iqProject + "\"," + System.lineSeparator()
        + "\"sonatypeProjectStage\": \"" + iqProjectStage + "\"," + System.lineSeparator()
        + "\"fortifyApplication\": \"" + sscApplication + "\"," + System.lineSeparator()
        + "\"fortifyApplicationVersion\": \"" + sscApplicationVersion + "\"" + System.lineSeparator() + "}";
  }

}
