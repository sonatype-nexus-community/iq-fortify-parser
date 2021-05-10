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
import org.springframework.context.annotation.PropertySource;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.sonatype.ssc.intsvc.iq.webhook.ApplicationEvaluation;
import com.sonatype.ssc.intsvc.iq.webhook.ApplicationEvaluationPayload;
import com.sonatype.ssc.intsvc.util.ApplicationPropertiesLoader;

import org.apache.commons.lang3.ObjectUtils;

@PropertySource("file:iqapplication.properties")
@RestController
@Validated
public class SonatypeController
{
  @Autowired
  private IQFortifyIntegrationService iqFortifyIntgSrv;

  private static final Logger logger = Logger.getRootLogger();

  /**
   * This is the core service which loads the Sonatype vulnerability and uploads it
   * fortify server using mappings file mapping.json
   *
   * @return String.
   */
  @GetMapping(value = "startScanLoad")
  public String startScanLoad(
          @RequestParam(value=IQSSCMapping.IQ_PROJECT, required=false) String iqProject,
          @RequestParam(value=IQSSCMapping.IQ_PROJECT_STAGE, required=false) String iqProjectStage,
          @RequestParam(value=IQSSCMapping.SSC_APPLICATION, required=false) String sscApplication,
          @RequestParam(value=IQSSCMapping.SSC_APPLICATION_VERSION, required=false) String sscApplicationVersion,
          @RequestParam(value=IQSSCMapping.SAVE_MAPPING, required=false) Boolean saveMapping
  ) throws IOException {

    try (ApplicationProperties appProp = loadApplicationProperties()) {
      if (appProp == null) {
        return "FAILURE";
      }

      iqProject = sanitizeInput(iqProject);
      iqProjectStage = sanitizeInput(iqProjectStage);
      sscApplication = sanitizeInput(sscApplication);
      sscApplicationVersion = sanitizeInput(sscApplicationVersion);

      if (ObjectUtils.allNotNull(iqProject, iqProjectStage, sscApplication, sscApplicationVersion)) {
        logger.info("In startScanLoad: Processing passed IQ-SSC mapping instead of mapping.json");
        IQSSCMapping mapping = new IQSSCMapping(iqProject, iqProjectStage, sscApplication, sscApplicationVersion);
        iqFortifyIntgSrv.startLoad(appProp, mapping, saveMapping);
      } else {
        iqFortifyIntgSrv.startLoad(appProp);
      }
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

  private static final String MSG_SCH_SEPRATOR = "###############################################################################";

  /**
   * This method is scheduled as defined in configuration file.
   */
  @Scheduled(cron = "${scheduling.job.cron}")
  public void runScheduledLoad() throws IOException {

    try (ApplicationProperties appProp = loadApplicationProperties()) {
      if (appProp == null) {
        logger.info(MSG_SCH_SEPRATOR);
        return;
      }

      long start = System.currentTimeMillis();
      logger.info("Scheduler run started");

      iqFortifyIntgSrv.startLoad(appProp);

      logger.info("Scheduler run completed");
      long end = System.currentTimeMillis();
      logger.info("Scheduler run took " + (end - start) / 1000 + " seconds");
      logger.info(MSG_SCH_SEPRATOR);

      if (appProp.getIsKillTrue()) {
        logger.info("Stopping service as configured in iqapplication.properties");
        iqFortifyIntgSrv.killProcess();
        logger.fatal("process should have been killed...");
        return;
      }
    }
  }

  // https://help.sonatype.com/iqserver/automating/iq-server-webhooks#IQServerWebhooks-ExampleHeadersandPayloads
  @PostMapping(path = "webhook/iq", consumes = "application/json", headers = "x-nexus-webhook-id=iq:applicationEvaluation")
  public String webhook(@RequestBody ApplicationEvaluationPayload payload) throws IOException {
    ApplicationEvaluation eval = payload.getApplicationEvaluation();
    ApplicationEvaluation.Application app = eval.getApplication();

    logger.debug("Webhook received: " + app.getName() + " (" + app.getPublicId() + ", " + app.getId() + "), stage: " + eval.getStage());

    String iqProject = app.getPublicId();
    String iqProjectStage = eval.getStage();

    try (ApplicationProperties appProp = loadApplicationProperties()) {
      if (appProp == null) {
        return "FAILURE";
      }

      // look for a mapping
      IQSSCMapping mapping = null;
      for (IQSSCMapping m : iqFortifyIntgSrv.loadMapping(appProp)) {
        if (iqProject.equals(m.getIqProject()) && iqProjectStage.equals(m.getIqProjectStage())) {
          mapping = m;
          break;
        }
      }

      // report unknown mapping, or start load
      if (mapping == null) {
        logger.warn("No mapping found for " + iqProject + " with phase " + iqProjectStage);
        return "FAILURE";
      } else {
        iqFortifyIntgSrv.startLoad(appProp, mapping, false);
      }
    }

    return "SUCCESS";
  }

  private ApplicationProperties loadApplicationProperties() {
    try {
      ApplicationProperties appProp = ApplicationPropertiesLoader.loadProperties();

      if (appProp.getMissingReqProp()) {
        logger.fatal("Error in reading properties file exiting the data load process.");
        return null;
      }

      return appProp;
    } catch (FileNotFoundException e) {
      logger.fatal("iqapplication.properties file not found ::", e);
    } catch (IOException e) {
      logger.fatal("IOException exception in reading iqapplication.properties ::", e);
    }
    return null;
  }
}
