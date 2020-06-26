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
package com.sonatype.ssc.intsvc.util;

import java.util.Properties;

import org.apache.log4j.Logger;

import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class ApplicationProperty
{
  private ApplicationProperty() {
    throw new IllegalStateException("ApplicationProperty class");
  }

  private static final Logger logger = Logger.getRootLogger();

  public static ApplicationProperties loadProperties() throws IOException {
    ApplicationProperties appProp = new ApplicationProperties();
    File file = new File("iqapplication.properties");
    FileInputStream fileInput = new FileInputStream(file);
    Properties properties = new Properties();
    properties.load(fileInput);
    appProp.setMissingReqProp(false);

    if (!setIQServerProperties(appProp, properties)) {
      appProp.setMissingReqProp(true);
    }

    if (!setSSCServerProperties(appProp, properties)) {
      appProp.setMissingReqProp(true);
    }

    String mapFile = properties.getProperty("mapping.file");

    String iqReportType = properties.getProperty("iq.report.type");
    appProp.setIqReportType(iqReportType);

    if (verifyIsNotNull(mapFile, SonatypeConstants.ERR_MAP_JSON_MISSING)) {
      appProp.setMapFile(mapFile);
    }
    else {
      appProp.setMissingReqProp(true);
    }

    String loadfileLocation = properties.getProperty("loadfile.location");
    if (verifyIsNotNull(loadfileLocation)) {
      appProp.setLoadLocation(loadfileLocation);
    }
    else {
      appProp.setLoadLocation("./");
    }

    appProp.setIsKillTrue(new Boolean(properties.getProperty("KillProcess")));
    fileInput.close();

    return appProp;
  }

  private static boolean setSSCServerProperties(ApplicationProperties iqProp, Properties properties) {
    boolean hasReqProp = true;

    String sscServerURL = properties.getProperty("sscserver.url");
    if (verifyIsNotNull(sscServerURL, SonatypeConstants.ERR_SSC_URL_MISSING)) {
      iqProp.setSscServer(sscServerURL);
    }
    else {
      hasReqProp = false;
    }

    String sscServerUser = properties.getProperty("sscserver.username");
    if (verifyIsNotNull(sscServerUser, SonatypeConstants.ERR_SSC_USER_MISSING)) {
      iqProp.setSscServerUser(sscServerUser);
    }
    else {
      hasReqProp = false;
    }

    String sscServerPassword = properties.getProperty("sscserver.password");
    if (verifyIsNotNull(sscServerPassword, SonatypeConstants.ERR_SSC_PASS_MISSING)) {
      iqProp.setSscServerPassword(sscServerPassword);
    }
    else {
      hasReqProp = false;
    }

    return hasReqProp;
  }

  private static boolean setIQServerProperties(ApplicationProperties iqProp, Properties properties) {
    boolean hasReqProp = true;
    String iqServerURL = properties.getProperty("iqserver.url");
    if (verifyIsNotNull(iqServerURL, SonatypeConstants.ERR_IQ_URL_MISSING)) {
      iqProp.setIqServer(iqServerURL);
    }
    else {
      hasReqProp = false;
    }

    String iqServerUser = properties.getProperty("iqserver.username");
    if (verifyIsNotNull(iqServerUser, SonatypeConstants.ERR_IQ_USER_MISSING)) {
      iqProp.setIqServerUser(iqServerUser);
    }
    else {
      hasReqProp = false;
    }

    String iqServerPassword = properties.getProperty("iqserver.password");
    if (verifyIsNotNull(iqServerPassword, SonatypeConstants.ERR_IQ_PASS_MISSING)) {
      iqProp.setIqServerPassword(properties.getProperty("iqserver.password"));
    }
    else {
      hasReqProp = false;
    }

    return hasReqProp;
  }

  private static boolean verifyIsNotNull(String propValue, String errorMsg) {
    boolean isNotNull = true;
    if (propValue == null || propValue.isEmpty()) {
      isNotNull = false;
      logger.fatal(errorMsg);
    }
    return isNotNull;
  }

  private static boolean verifyIsNotNull(String propValue) {
    boolean isNotNull = true;

    if (propValue == null || propValue.isEmpty()) {
      isNotNull = false;
    }

    return isNotNull;
  }
}