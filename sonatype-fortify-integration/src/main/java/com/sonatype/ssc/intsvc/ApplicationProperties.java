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

import java.io.Closeable;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.iq.IQClient;
import com.sonatype.ssc.intsvc.ssc.SSCClient;

public class ApplicationProperties implements Closeable
{
  @Override
  public void close() {
    if (iqClient != null) {
      iqClient.close();
      iqClient = null;
    }
    if (sscClient != null) {
      sscClient.close();
      sscClient = null;
    }
  }

  private IQClient iqClient;

  public IQClient getIqClient() {
    if (iqClient == null) {
      iqClient = new IQClient(iqServer, iqServerUser, iqServerPassword, iqReportType);
    }
    return iqClient;
  }

  private String iqServer;

  public void setIqServer(String iqServer) {
    this.iqServer = iqServer;
  }

  private String iqServerUser;

  public void setIqServerUser(String iqServerUser) {
    this.iqServerUser = iqServerUser;
  }

  private String iqServerPassword;

  public void setIqServerPassword(String iqServerPassword) {
    this.iqServerPassword = iqServerPassword;
  }

  private String iqReportType;

  public void setIqReportType(String iqReportType) {
    this.iqReportType = iqReportType;
  }

  private SSCClient sscClient;

  public SSCClient getSscClient() {
    if (sscClient == null) {
      sscClient = new SSCClient(sscServer, sscServerToken);
    }
    return sscClient;
  }

  private String sscServer;

  public void setSscServer(String sscServer) {
    this.sscServer = sscServer;
  }

  private String sscServerToken;

  public void setSscServerToken(String sscServerToken) {
    this.sscServerToken = sscServerToken;
  }

  private File mapFile;

  public File getMapFile() {
    return mapFile;
  }

  public void setMapFile(File mapFile) {
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

  private File loadLocation;

  public File getLoadLocation() {
    return loadLocation;
  }

  public void setLoadLocation(File loadLocation) {
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
    if (StringUtils.isNotBlank(logLevel)) {
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
