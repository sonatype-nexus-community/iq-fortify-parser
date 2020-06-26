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
package com.sonatype.ssc.intsvc;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.IQSSCMapping;

public class ApplicationProperties
{
  private String iqServer;

  public String getIqServer() {
    return checkTrailingSlash(iqServer);
  }

  public void setIqServer(String iqServer) {
    this.iqServer = iqServer;
  }

  private String iqServerUser;

  public String getIqServerUser() {
    return iqServerUser;
  }

  public void setIqServerUser(String iqServerUser) {
    this.iqServerUser = iqServerUser;
  }

  private String iqServerPassword;

  public String getIqServerPassword() {
    return iqServerPassword;
  }

  public void setIqServerPassword(String iqServerPassword) {
    this.iqServerPassword = iqServerPassword;
  }

  private String sscServer;

  public String getSscServer() {
    return checkTrailingSlash(sscServer);
  }

  public void setSscServer(String sscServer) {
    this.sscServer = sscServer;
  }

  private String sscServerUser;

  public String getSscServerUser() {
    return sscServerUser;
  }

  public void setSscServerUser(String sscServerUser) {
    this.sscServerUser = sscServerUser;
  }

  private String sscServerPassword;

  public String getSscServerPassword() {
    return sscServerPassword;
  }

  public void setSscServerPassword(String sscServerPassword) {
    this.sscServerPassword = sscServerPassword;
  }

  public String getIqReportType() {
    return iqReportType;
  }

  public void setIqReportType(String iqReportType) {
    this.iqReportType = iqReportType;
  }

  private String iqReportType;

  private String mapFile;

  public String getMapFile() {
    return mapFile;
  }

  public void setMapFile(String mapFile) {
    this.mapFile = mapFile;
  }

  public List<IQSSCMapping> loadMapping() throws IOException, ParseException {
    List<IQSSCMapping> applicationList = new ArrayList<>();
    try (Reader reader = new FileReader(mapFile)) {
      JSONArray jArray = (JSONArray) new JSONParser().parse(reader);
      for (Object item : jArray) {
        JSONObject application = (JSONObject) item;
        String iqProject = (String) application.get(SonatypeConstants.IQ_PROJECT);
        String iqProjectStage = (String) application.get(SonatypeConstants.IQ_PROJECT_STAGE);
        String sscApplication = (String) application.get(SonatypeConstants.SSC_APPLICATION);
        String sscApplicationVersion = (String) application.get(SonatypeConstants.SSC_APPLICATION_VERSION);
        applicationList.add(new IQSSCMapping(iqProject, iqProjectStage, sscApplication, sscApplicationVersion));
      }
      return applicationList;
    }
  }

  private String loadLocation;

  public String getLoadLocation() {
    return loadLocation;
  }

  public void setLoadLocation(String loadLocation) {
    this.loadLocation = loadLocation;
  }

  private String logFileLocation;

  public String getLogFileLocation() {
    return logFileLocation;
  }

  public void setLogFileLocation(String logFileLocation) {
    this.logFileLocation = logFileLocation;
  }

  private boolean isKillTrue;

  public boolean getIsKillTrue() {
    return isKillTrue;
  }

  public void setIsKillTrue(boolean isKillTrue) {
    this.isKillTrue = isKillTrue;
  }

  private boolean missingReqProp;

  public boolean getMissingReqProp() {
    return missingReqProp;
  }

  public void setMissingReqProp(boolean missingReqProp) {
    this.missingReqProp = missingReqProp;
  }

  private String logLevel;

  public String getLogLevel() {
    return logLevel;
  }

  public void setLogLevel(String logLevel) {
    if (logLevel != null && logLevel.trim().length() > 0) {
      this.logLevel = logLevel;
    }
    else {
      this.logLevel = "DEBUG";
    }
  }

  private String checkTrailingSlash(String website) {
    return website.endsWith("/") ? website : website + "/";
  }
}
