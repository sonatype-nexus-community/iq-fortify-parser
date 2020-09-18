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

/**
 * Utility to load iqapplication.properties configuration.
 */
public class ApplicationPropertiesLoader
{
  private ApplicationPropertiesLoader() {
    throw new IllegalStateException("ApplicationPropertiesLoader class");
  }

  private static final Logger logger = Logger.getRootLogger();

  public static ApplicationProperties loadProperties() throws IOException {
    File file = new File("iqapplication.properties");
    Properties properties = new Properties();
    try (FileInputStream fileInput = new FileInputStream(file)) {
      properties.load(fileInput);
    }

    ApplicationProperties appProp = new ApplicationProperties();

    if (!setIQServerProperties(appProp, properties)) {
      appProp.setMissingReqProp(true);
    }

    if (!setSSCServerProperties(appProp, properties)) {
      appProp.setMissingReqProp(true);
    }

    String mapFile = properties.getProperty("mapping.file");

    if (verifyIsNotNull(mapFile, SonatypeConstants.ERR_MAP_JSON_MISSING)) {
      appProp.setMapFile(new File(mapFile));
    }
    else {
      appProp.setMissingReqProp(true);
    }

    String iqReportType = properties.getProperty("iq.report.type", "policy");
    if (!("policy".equals(iqReportType) || "vulnerabilities".equals(iqReportType) || "raw".equals(iqReportType))) {
      logger.warn("Invalid iq.report.type '" + iqReportType + "': using default 'policy'");
      iqReportType = "policy";
    }
    appProp.setIqReportType(iqReportType);

    appProp.setPriorityCritical(Integer.parseInt(properties.getProperty("priority.critical", "8")));
    appProp.setPriorityHigh(Integer.parseInt(properties.getProperty("priority.high", "4")));
    appProp.setPriorityMedium(Integer.parseInt(properties.getProperty("priority.medium", "2")));

    String loadfileLocation = properties.getProperty("loadfile.location");
    if (verifyIsNotNull(loadfileLocation)) {
      appProp.setLoadLocation(new File(loadfileLocation));
    }
    else {
      appProp.setLoadLocation(new File("./"));
    }
    if (!appProp.getLoadLocation().canWrite()) {
      appProp.setMissingReqProp(true);
      if (!appProp.getLoadLocation().canRead()) {
        logger.fatal(SonatypeConstants.ERR_LOADFILE_LOCATION_CANT_READ + appProp.getLoadLocation());
      }
      else {
        logger.fatal(SonatypeConstants.ERR_LOADFILE_LOCATION_CANT_WRITE + appProp.getLoadLocation());
      }
    }

    appProp.setIsKillTrue(Boolean.parseBoolean(properties.getProperty("KillProcess")));

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

    String sscServerToken = properties.getProperty("sscserver.token");
    if (verifyIsNotNull(sscServerURL, SonatypeConstants.ERR_SSC_TOKEN_MISSING)) {
      iqProp.setSscServerToken(sscServerToken);
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
