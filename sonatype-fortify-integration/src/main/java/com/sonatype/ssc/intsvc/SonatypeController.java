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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.LinkedHashMap;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.service.IQFortifyIntegrationService;
import com.sonatype.ssc.intsvc.util.ApplicationProperty;
import com.sonatype.ssc.intsvc.util.LoggerUtil;

import org.apache.commons.lang3.ObjectUtils;

@PropertySource("file:iqapplication.properties")
@RestController
@Validated
public class SonatypeController
{
  @Autowired
  private IQFortifyIntegrationService iqFortifyIntgSrv;

  @Value("${logfile.location:./Service.log}")
  private String logfileLocation;

  @Value("${logLevel:DEBUG}")
  private String logLevel;

  private static final Logger logger = Logger.getRootLogger();

  /**
   * This is the core service which loads the sonatype vulnerabilty and uploads it
   * fortify server using mappings file mapping.json
   *
   * @return String.
   */
  @GetMapping(value = "startScanLoad")
  public String startScanLoad(
          @RequestParam(value=SonatypeConstants.IQ_PROJECT, required=false) String sonatypeProject,
          @RequestParam(value=SonatypeConstants.IQ_PROJECT_STAGE, required=false) String sonatypeProjectStage,
          @RequestParam(value=SonatypeConstants.SSC_APPLICATION, required=false) String fortifyApplication,
          @RequestParam(value=SonatypeConstants.SSC_APPLICATION_VERSION, required=false) String fortifyApplicationVersion,
          @RequestParam(value=SonatypeConstants.SAVE_MAPPING, required=false) Boolean saveMapping
  ) throws IOException {
    ApplicationProperties appProp = null;
    Logger log = LoggerUtil.getLogger(logger, logfileLocation, logLevel);

    try {
      appProp = ApplicationProperty.loadProperties();
      String validationString = "[\n|\r|\t]";
      String validationReplace = "_";
      sonatypeProject = sonatypeProject.replaceAll(validationString, validationReplace);
      sonatypeProjectStage = sonatypeProjectStage.replaceAll(validationString, validationReplace);
      fortifyApplication = fortifyApplication.replaceAll(validationString, validationReplace);
      fortifyApplicationVersion = fortifyApplicationVersion.replaceAll(validationString, validationReplace);
    }
    catch (FileNotFoundException e) {
      log.fatal(SonatypeConstants.ERR_PRP_NOT_FND + e.getMessage());
    }
    catch (IOException e) {
      log.fatal(SonatypeConstants.ERR_IO_EXCP + e.getMessage());
    }
    if (ObjectUtils.allNotNull(sonatypeProject,sonatypeProjectStage,fortifyApplication,fortifyApplicationVersion) && appProp != null) {

      logger.info("In startScanLoad: Processing passed project map instead of mapping.json");
      LinkedHashMap<String, String> projectMap = new LinkedHashMap<>();
      projectMap.put(SonatypeConstants.IQ_PRJ, sonatypeProject);
      projectMap.put(SonatypeConstants.IQ_STG, sonatypeProjectStage);
      projectMap.put(SonatypeConstants.SSC_APP, fortifyApplication);
      projectMap.put(SonatypeConstants.SSC_VER, fortifyApplicationVersion);

      iqFortifyIntgSrv.startLoad(appProp, projectMap, saveMapping);
    } else if (appProp != null) {
      iqFortifyIntgSrv.startLoad(appProp, null, false);
    }
    else {
      log = LoggerUtil.getLogger(logger, "", "");
      log.error(SonatypeConstants.ERR_READ_PRP);
    }

    log.removeAllAppenders();
    return "SUCCESS";
  }

  @GetMapping(value = "killProcess")
  public String killProcess() {
    return iqFortifyIntgSrv.killProcess();
  }

  @GetMapping(value = "waivePolicy/{policyViolationId}/{scope}")
  public String waivePolicy(
      @PathVariable String policyViolationId,
      @PathVariable String scope
  ) {
    Logger log = LoggerUtil.getLogger(logger, logfileLocation, logLevel);
    log.info("Request for waivePolicy with policyId: " + policyViolationId + " and scope: " + scope);
    return "";
  }
}