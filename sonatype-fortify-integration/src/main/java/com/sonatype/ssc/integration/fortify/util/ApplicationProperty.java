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
package com.sonatype.ssc.integration.fortify.util;

import java.util.Properties;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import com.sonatype.ssc.integration.fortify.model.IQProperties;
import com.sonatype.ssc.integration.fortify.constants.SonatypeConstants;

public class ApplicationProperty
{
  private ApplicationProperty() {
    throw new IllegalStateException("ApplicationProperty class");
  }

  private static final Logger logger = Logger.getRootLogger();

  public static IQProperties loadProperties() throws IOException {
    IQProperties iqProp = new IQProperties();
    File file = new File("iqapplication.properties");
    FileInputStream fileInput = new FileInputStream(file);
    Properties properties = new Properties();
    properties.load(fileInput);
    iqProp.setMissingReqProp(false);

    if (!setIQServerProperties(iqProp, properties)) {
      iqProp.setMissingReqProp(true);
    }

    if (!setSSCServerProperties(iqProp, properties)) {
      iqProp.setMissingReqProp(true);
    }

    String mapFile = properties.getProperty("mapping.file");

    String iqReportType = properties.getProperty("iq.report.type");
    iqProp.setIqReportType(iqReportType);

    if (verifyIsNotNull(mapFile, SonatypeConstants.ERR_MAP_JSON_MISSING)) {
      iqProp.setMapFile(mapFile);
    }
    else {
      iqProp.setMissingReqProp(true);
    }

    String loadfileLocation = properties.getProperty("loadfile.location");
    if (verifyIsNotNull(loadfileLocation)) {
      iqProp.setLoadLocation(loadfileLocation);
    }
    else {
      iqProp.setLoadLocation("./");
    }

    iqProp.setIsKillTrue(new Boolean(properties.getProperty("KillProcess")));
    fileInput.close();

    return iqProp;
  }

  private static boolean setSSCServerProperties(IQProperties iqProp, Properties properties) {
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

  private static boolean setIQServerProperties(IQProperties iqProp, Properties properties) {
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
