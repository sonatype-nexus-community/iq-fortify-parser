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
import com.sonatype.ssc.intsvc.util.ApplicationPropertiesLoader;

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
   * This is the core service which loads the sonatype vulnerability and uploads it
   * fortify server using mappings file mapping.json
   *
   * @return String.
   */
  @GetMapping(value = "startScanLoad")
  public String startScanLoad(
          @RequestParam(value=SonatypeConstants.IQ_PROJECT, required=false) String iqProject,
          @RequestParam(value=SonatypeConstants.IQ_PROJECT_STAGE, required=false) String iqProjectStage,
          @RequestParam(value=SonatypeConstants.SSC_APPLICATION, required=false) String sscApplication,
          @RequestParam(value=SonatypeConstants.SSC_APPLICATION_VERSION, required=false) String sscApplicationVersion,
          @RequestParam(value=SonatypeConstants.SAVE_MAPPING, required=false) Boolean saveMapping
  ) throws IOException {
    ApplicationProperties appProp = null;
    try {
      appProp = ApplicationPropertiesLoader.loadProperties();
    } catch (FileNotFoundException e) {
      logger.fatal(SonatypeConstants.ERR_PRP_NOT_FND + e.getMessage());
    } catch (IOException e) {
      logger.fatal(SonatypeConstants.ERR_IO_EXCP + e.getMessage());
    }
    if (appProp.getMissingReqProp()) {
      logger.error(SonatypeConstants.ERR_READ_PRP);
      return "FAILURE";
    }

    iqProject = sanitizeInput(iqProject);
    iqProjectStage = sanitizeInput(iqProjectStage);
    sscApplication = sanitizeInput(sscApplication);
    sscApplicationVersion = sanitizeInput(sscApplicationVersion);

    try {
      if (ObjectUtils.allNotNull(iqProject, iqProjectStage, sscApplication, sscApplicationVersion)) {
        logger.info("In startScanLoad: Processing passed IQ-SSC mapping instead of mapping.json");
        IQSSCMapping mapping = new IQSSCMapping(iqProject, iqProjectStage, sscApplication, sscApplicationVersion);
        iqFortifyIntgSrv.startLoad(appProp, mapping, saveMapping);
      } else {
        iqFortifyIntgSrv.startLoad(appProp);
      }
    } finally {
      appProp.close();
    }
    return "SUCCESS";
  }

  private String sanitizeInput(String input) {
    return input == null ? input : input.replaceAll("[\n|\r|\t]", "_");
  }

  @GetMapping(value = "killProcess")
  public String killProcess() {
    logger.info("Stopping service as configured as requested by /killProcess");
    return iqFortifyIntgSrv.killProcess();
  }

  @GetMapping(value = "waivePolicy/{policyViolationId}/{scope}")
  public String waivePolicy(
      @PathVariable String policyViolationId,
      @PathVariable String scope
  ) {
    logger.info("Request for waivePolicy with policyId: " + policyViolationId + " and scope: " + scope);
    return "";
  }
}
