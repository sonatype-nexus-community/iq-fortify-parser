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
package com.sonatype.ssc.intsvc;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.log4j.Logger;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;

/**
 * Mapping from a Nexus Lifecycle/IQ "project" (IQ application id) + stage to a Fortify SSC application + version.
 */
public class IQSSCMapping {
  public static final String IQ_PROJECT = "sonatypeProject";

  public static final String IQ_PROJECT_STAGE = "sonatypeProjectStage";

  public static final String SSC_APPLICATION = "fortifyApplication";

  public static final String SSC_APPLICATION_VERSION = "fortifyApplicationVersion";

  public static final String SAVE_MAPPING = "saveMapping";

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

  public boolean verifyMapping(Logger logger) {
    boolean success = true;

    if (StringUtils.isBlank(iqProject)) {
      logger.error(SonatypeConstants.ERR_IQ_PRJ);
      success = false;
    }
    if (StringUtils.isBlank(iqProjectStage)) {
      logger.error(SonatypeConstants.ERR_IQ_PRJ_STG);
      success = false;
    }
    if (StringUtils.isBlank(sscApplication)) {
      logger.error(SonatypeConstants.ERR_SSC_APP);
      success = false;
    }
    if (StringUtils.isBlank(sscApplicationVersion)) {
      logger.error(SonatypeConstants.ERR_SSC_APP_VER);
      success = false;
    }

    return success;
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
