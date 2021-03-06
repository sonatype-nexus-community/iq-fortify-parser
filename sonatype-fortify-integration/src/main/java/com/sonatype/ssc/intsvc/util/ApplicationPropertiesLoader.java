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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Utility to load {@code iqapplication.properties} configuration into an {@link ApplicationProperties}.
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

    if (verifyIsNotNull(mapFile, "Missing IQ to SSC mapping file name from iqapplication.properties, it's a required property.")) {
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
        logger.fatal("loadfile location from iqapplication.properties points to a directory that can't be read, it's a required property to an existing directory: " + appProp.getLoadLocation());
      }
      else {
        logger.fatal("loadfile location from iqapplication.properties points to a directory that can't be written to, it's a required property to a directory with write access: " + appProp.getLoadLocation());
      }
    }

    appProp.setIsKillTrue(Boolean.parseBoolean(properties.getProperty("KillProcess")));

    return appProp;
  }

  private static boolean setSSCServerProperties(ApplicationProperties iqProp, Properties properties) {
    boolean hasReqProp = true;

    String sscServerURL = properties.getProperty("sscserver.url");
    if (verifyIsNotNull(sscServerURL, "Missing SSC Server URL from iqapplication.properties, it's a required property.")) {
      iqProp.setSscServer(sscServerURL);
    }
    else {
      hasReqProp = false;
    }

    String sscServerToken = properties.getProperty("sscserver.token");
    if (verifyIsNotNull(sscServerToken, "Missing SSC Server token (CIToken) from iqapplication.properties, it's a required property.")) {
      iqProp.setSscServerToken(sscServerToken);
    }
    else {
      if (verifyIsNotNull(properties.getProperty("sscserver.username"))
          || verifyIsNotNull(properties.getProperty("sscserver.password"))) {
        logger.fatal("Old SSC user+password authentication removed, current integration service requires SSC 20 minimum and token authentication: see sample iqapplication.properties");
      }
      hasReqProp = false;
    }

    return hasReqProp;
  }

  private static boolean setIQServerProperties(ApplicationProperties iqProp, Properties properties) {
    boolean hasReqProp = true;
    String iqServerURL = properties.getProperty("iqserver.url");
    if (verifyIsNotNull(iqServerURL, "Missing IQ Server URL from iqapplication.properties, it's a required property.")) {
      iqProp.setIqServer(iqServerURL);
    }
    else {
      hasReqProp = false;
    }

    String iqServerUser = properties.getProperty("iqserver.username");
    if (verifyIsNotNull(iqServerUser, "Missing IQ Server username from iqapplication.properties, it's a required property.")) {
      iqProp.setIqServerUser(iqServerUser);
    }
    else {
      hasReqProp = false;
    }

    String iqServerPassword = properties.getProperty("iqserver.password");
    if (verifyIsNotNull(iqServerPassword, "Missing IQ Server password from iqapplication.properties, it's a required property.")) {
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
