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
package com.sonatype.ssc.intsvc.service;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.*;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Component;
import com.sonatype.ssc.intsvc.model.PolicyViolation.PolicyViolationResponse;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Violation;
import com.sonatype.ssc.intsvc.model.Remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.VulnDetailResponse;
import com.sonatype.ssc.intsvc.util.IQClient;
import com.sonatype.ssc.intsvc.util.SSCClient;

@Service
public class IQFortifyIntegrationService
{
  private static final Logger logger = Logger.getRootLogger();

  public void startLoad(ApplicationProperties appProp) throws IOException {
    int totalCount = 0;
    int successCount = 0;
    List<IQSSCMapping> applicationList = loadMapping(appProp);
    if (applicationList != null && !(applicationList.isEmpty())) {
      Iterator<IQSSCMapping> iterator = applicationList.iterator();
      while (iterator.hasNext()) {
        totalCount++;
        IQSSCMapping applicationMapping = iterator.next();
        if (startLoadProcess(applicationMapping, appProp)) {
          successCount++;
        }
      }
    }
    logger.info(SonatypeConstants.MSG_DATA_CMP);
    logger.info(SonatypeConstants.MSG_TOT_CNT + totalCount);
    logger.info(SonatypeConstants.MSG_IQ_CNT + successCount + " projects");
  }

  public void startLoad(ApplicationProperties appProp, IQSSCMapping iqSscMapping, boolean saveMapping) throws IOException {
    if (startLoadProcess(iqSscMapping, appProp)) {
      if (saveMapping) {
        //TODO: Save the passed mapping to the mapping file
      }
    }
    logger.info(SonatypeConstants.MSG_DATA_CMP);
  }

  private boolean startLoadProcess(IQSSCMapping iqSscMapping, ApplicationProperties appProp) throws IOException {
    boolean success = false;
    if (verifyMapping(iqSscMapping)) {
      // get data from IQ
      String iqDataFile = getIQVulnerabilityData(iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp);

      if (iqDataFile != null && iqDataFile.length() > 0) {
        // save data to SSC
        logger.info(SonatypeConstants.MSG_SSC_DATA_WRT + iqDataFile);
        if (loadDataIntoSSC(iqSscMapping, appProp, iqDataFile)) {
          success = true;
        }
      }
    }
    return success;
  }

  private boolean verifyMapping(IQSSCMapping iqSscMapping) {
    boolean success = true;

    String iqProject = iqSscMapping.getIqProject();
    String iqPhase = iqSscMapping.getIqProjectStage();
    String sscAppName = iqSscMapping.getSscApplication();
    String sscAppVersion = iqSscMapping.getSscApplicationVersion();

    if (!(iqProject != null && iqProject.trim().length() > 0)) {
      logger.error(SonatypeConstants.ERR_IQ_PRJ);
      success = false;
    }
    if (!(iqPhase != null && iqPhase.trim().length() > 0)) {
      logger.error(SonatypeConstants.ERR_IQ_PRJ_STG);
      success = false;
    }
    if (!(sscAppName != null && sscAppName.trim().length() > 0)) {
      logger.error(SonatypeConstants.ERR_SSC_APP);
      success = false;
    }
    if (!(sscAppVersion != null && sscAppVersion.trim().length() > 0)) {
      logger.error(SonatypeConstants.ERR_SSC_APP_VER);
      success = false;
    }

    return success;
  }

  private List<IQSSCMapping> loadMapping(ApplicationProperties appProp) {
    List<IQSSCMapping> emptyList = new ArrayList<>();
    try {
      return appProp.loadMapping();
    }
    catch (FileNotFoundException e) {
      logger.fatal(SonatypeConstants.ERR_MISSING_JSON + e.getMessage());
      return emptyList;
    }
    catch (IOException e) {
      logger.fatal(SonatypeConstants.ERR_IOEXCP_JSON + e.getMessage());
      return emptyList;
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_EXCP_JSON + e.getMessage());
      return emptyList;
    }
  }

  private String getIQVulnerabilityData(String project, String version, ApplicationProperties appProp) {

    logger.debug(SonatypeConstants.MSG_READ_IQ_1 + project + SonatypeConstants.MSG_READ_IQ_2 + version);
    IQClient iqClient = new IQClient(appProp);
    String fileName = "";

    String internalAppId = iqClient.getInternalApplicationId(project);
    logger.debug("Got internal application id from IQ: " + internalAppId + " for " + project);

    if (internalAppId != null && internalAppId.length() > 0) {
      IQProjectData iqProjectData = iqClient.getIQProjectData(internalAppId, version, project);

      if (iqProjectData.getProjectReportURL() != null && iqProjectData.getProjectReportURL().length() > 0) {

        if (isNewLoad(project, version, appProp, iqProjectData)) {

          //TODO: Get the policy based report here.
          String iqPolicyReportResults = iqClient.getPolicyReport(project, iqProjectData.getProjectReportId());
          logger.debug("** In getIQVulnerabilityData.  iqPolicyReportResults: " + iqPolicyReportResults);

          //TODO: Parse the results of the policy violation report
          try {
            PolicyViolationResponse policyViolationResponse = (new ObjectMapper()).readValue(iqPolicyReportResults,
                PolicyViolationResponse.class);
            logger.debug("** Finding Current Count: " + countFindings(project, version, appProp));

            logger.debug("** before parsePolicyViolationResults");
            ArrayList<IQProjectVulnerability> finalProjectVulMap = parsePolicyViolationResults(policyViolationResponse, appProp, iqProjectData);
            if (finalProjectVulMap == null) {
                return null;
            }

            // ArrayList<IQProjectVulnerability> finalProjectVulMap =
            // readVulData(iqPolicyReport, appProp, iqProjectData);

            String projectIQReportURL = SonatypeConstants.IQ_REPORT_URL + '/' + iqProjectData.getProjectName() + '/'
                + iqProjectData.getProjectReportId() + '/' + appProp.getIqReportType();

            iqProjectData.setTotalComponentCount(policyViolationResponse.getCounts().getTotalComponentCount());
            iqProjectData.setProjectIQReportURL(projectIQReportURL);

            logger.debug("** before saveIqDataAsJSON: " + iqProjectData.toString());
            fileName = iqClient.saveIqDataAsJSON(iqProjectData, finalProjectVulMap, appProp.getIqServer(),
                    appProp.getLoadLocation());

          } catch (Exception e) {
            logger.error("policyViolationResponse: " + e.getMessage());
          }

        }
        else {
          logger.info(SonatypeConstants.MSG_EVL_SCAN_SAME_1 + project + SonatypeConstants.MSG_EVL_SCAN_SAME_2
              + version + SonatypeConstants.MSG_EVL_SCAN_SAME_3);
        }
      }
      else {
        logger.info(SonatypeConstants.MSG_NO_REP_1 + project + SonatypeConstants.MSG_NO_REP_2 + version
            + SonatypeConstants.MSG_NO_REP_3);
      }
    }
    else {
      logger.info(SonatypeConstants.MSG_NO_IQ_PRJ_1 + project + SonatypeConstants.MSG_NO_IQ_PRJ_2 + version
          + SonatypeConstants.MSG_NO_IQ_PRJ_3);
    }

    return fileName;
  }

  private ArrayList<IQProjectVulnerability> parsePolicyViolationResults(PolicyViolationResponse policyViolationResponse,
                                                        ApplicationProperties appProp,
                                                        IQProjectData iqProjectData) {

    logger.debug("** In parsePolicyViolationResults");
    IQClient iqClient = new IQClient(appProp);

    ArrayList<IQProjectVulnerability> finalProjectVulMap = new ArrayList<>();
    Pattern pattern = Pattern.compile("Found security vulnerability (.*) with");
      List<Component> components = policyViolationResponse.getComponents();

      for (Component component:components) {
        logger.debug("** component hash: " + component.getHash());
        if (component.getViolations() != null && component.getViolations().size() > 0) {
          for (Violation violation : component.getViolations()) {
            // If the violation is waived and is not a security category
            if (violation.getWaived() || violation.getGrandfathered() || !(violation.getPolicyThreatCategory().equalsIgnoreCase("SECURITY"))) {
              continue;
            }

            IQProjectVulnerability iqPrjVul = new IQProjectVulnerability();

            logger.debug("** condition reason: " + violation.getConstraints().get(0).getConditions().get(0).getConditionReason());
            Matcher matcher = pattern.matcher(violation.getConstraints().get(0).getConditions().get(0).getConditionReason());
            if (matcher.find()) {
              String CVE = matcher.group(1);
              logger.debug("CVE: " + CVE);
              iqPrjVul.setIssue(CVE);
              iqPrjVul.setCveurl(StringUtils.defaultString(iqClient.getVulnDetailURL(CVE, appProp)));

              iqPrjVul.setUniqueId(StringUtils.defaultString(violation.getPolicyViolationId()));
              iqPrjVul.setPackageUrl(StringUtils.defaultString(component.getPackageUrl()));
              iqPrjVul.setHash(StringUtils.defaultString(component.getHash()));
              if (component.getComponentIdentifier().getFormat().equalsIgnoreCase("composer")) {
                logger.debug("Component Identifier is composer: " + component.getComponentIdentifier().toString());
                iqPrjVul.setFileName(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getAdditionalProperties().get("name").toString()));
                iqPrjVul.setFormat(StringUtils.defaultString(component.getComponentIdentifier().getFormat()));
                iqPrjVul.setName(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getAdditionalProperties().get("name").toString()));
                iqPrjVul.setGroup(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getGroupId()));
                logger.debug("******** NAME: " + StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getAdditionalProperties().get("name").toString()));
                iqPrjVul.setVersion(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getVersion()));
              } else {
                iqPrjVul.setFileName(StringUtils.defaultString(component.getPackageUrl()));

                iqPrjVul.setName(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getArtifactId()));
                iqPrjVul.setFormat(StringUtils.defaultString(component.getComponentIdentifier().getFormat()));
                iqPrjVul.setArtifact(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getArtifactId()));
                iqPrjVul.setClassifier(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getClassifier()));
                iqPrjVul.setExtension(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getExtension()));
                iqPrjVul.setGroup(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getGroupId()));
                iqPrjVul.setVersion(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getVersion()));
              }

//              iqPrjVul.setMatchState(StringUtils.defaultString(component.getMatchState()));

              iqPrjVul.setSonatypeThreatLevel(StringUtils.defaultString(violation.getPolicyThreatLevel().toString()));

              String strResponseVulnDetails = iqClient.getVulnDetail(CVE, appProp);

              if (strResponseVulnDetails.equalsIgnoreCase("UNKNOWN")) {
                iqPrjVul.setVulnDetail(null);
                // Don't get the vuln details if we don't have
              } else {
                try {
                  VulnDetailResponse vulnDetailResponse = (new ObjectMapper()).readValue(strResponseVulnDetails,
                      VulnDetailResponse.class);
                  if (vulnDetailResponse != null) {
                    iqPrjVul.setVulnDetail(vulnDetailResponse);
                  }
                } catch (Exception e) {
                  logger.error("vulDetailRest: " + e.getMessage());
                }
              }

            try {

              iqPrjVul.setCompReportDetails(iqClient.getComponentDetails(iqPrjVul.getPackageUrl()));

              String componentRemediationResults = iqClient.getCompRemediation(iqProjectData, iqPrjVul.getPackageUrl());

              RemediationResponse remediationResponse = (new ObjectMapper()).readValue(componentRemediationResults,
                  RemediationResponse.class);

              if (remediationResponse != null) {
                iqPrjVul.setRemediationResponse(remediationResponse);
                logger.debug("** Setting remediation response for vulnerability details.");
              }
            } catch (Exception e) {
              logger.error("remediationResponse: " + e.getMessage());
            }


          }
            finalProjectVulMap.add(iqPrjVul);
          }
        }
      }
      logger.debug("finalProjectVulMap.size(): " + finalProjectVulMap.size());
      if (finalProjectVulMap.size() == countFindings(iqProjectData.getProjectName(), iqProjectData.getProjectStage(), appProp)) {
          logger.info("Findings count is equal for " + iqProjectData.getProjectName() + SonatypeConstants.MSG_EVL_SCAN_SAME_2
              + iqProjectData.getProjectStage() + SonatypeConstants.MSG_EVL_SCAN_SAME_3);
          return null;
      }
    return finalProjectVulMap;
  }


  private boolean isNewLoad(String project, String version, ApplicationProperties appProp, IQProjectData iqProjectData) {
    boolean isNewLoad = true;
    File prevFile = new File(appProp.getLoadLocation() + project + "_" + version + ".json");
    if (prevFile.exists()) {
      try {
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(new FileReader(prevFile));
        String scanDate = (String) json.get("scanDate");
        if (scanDate.equals(iqProjectData.getEvaluationDate())) {
          //TODO: For testing! make FALSE
          isNewLoad = true;
          //isNewLoad = false;
        }

      }
      catch (Exception e) {
        logger.error(SonatypeConstants.ERR_GET_IQ_DATA + e.getMessage());
      }

    }
    return isNewLoad;
  }

  private int countFindings(String project, String stage, ApplicationProperties appProp) {
    File prevFile = new File(appProp.getLoadLocation() + project + "_" + stage + ".json");
    if (prevFile.exists()) {
      try {
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(new FileReader(prevFile));
        JSONArray findings = (JSONArray) json.get("findings");
        if (!findings.isEmpty()) {
          return findings.size();
        }

      }
      catch (Exception e) {
        logger.error(SonatypeConstants.ERR_GET_IQ_DATA + e.getMessage());
      }

    }
    return 0;
  }

  private boolean loadDataIntoSSC(IQSSCMapping iqSscMapping, ApplicationProperties appProp, String iqDataFile)
      throws IOException
  {
    SSCClient sscClient = new SSCClient(appProp);
    boolean success = true;
    long sscAppId = sscClient.getSSCApplicationId(iqSscMapping.getSscApplication(), iqSscMapping.getSscApplicationVersion());
    if (sscAppId == 0) {
      sscAppId = sscClient.getNewSSCApplicationId(iqSscMapping.getSscApplication(), iqSscMapping.getSscApplicationVersion());
    }

    logger.debug("SSC Application id::" + sscAppId);
    if (sscAppId > 0) {
      try {
        if (!sscClient.uploadVulnerabilityByProjectVersion(sscAppId, new File(iqDataFile))) {
          backupLoadFile(iqDataFile, iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp.getLoadLocation());
          success = false;
        }
      }
      catch (Exception e) {
        success = false;
        logger.error(SonatypeConstants.ERR_SSC_APP_UPLOAD + e.getMessage());
        backupLoadFile(iqDataFile, iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp.getLoadLocation());
      }
    }
    else if (sscAppId == -1) {
      deleteLoadFile(iqDataFile);
      success = false;
    }
    else {
      logger.error(SonatypeConstants.ERR_SSC_CREATE_APP);
      deleteLoadFile(iqDataFile);
      success = false;
    }
    return success;
  }

  public String killProcess() {
    String os = System.getProperty("os.name");
    logger.debug("OS is ::" + os);
    String processName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
    String pId = processName.split("@")[0];
    logger.debug("pId is ::" + pId);
    if (os.startsWith("Windows")) {
      try {
        Runtime.getRuntime().exec("taskkill /F /PID " + pId);
        return "SUCCESS";
      }
      catch (IOException e) {
        logger.error(SonatypeConstants.ERR_KILL_PRC + e.getMessage());
        return "FAILED";
      }
    }
    else {
      try {
        Runtime.getRuntime().exec("kill -9 " + pId);
        return "SUCCESS";
      }
      catch (IOException e) {
        logger.error(e.getMessage());
        return "FAILED";
      }
    }
  }

  public void deleteLoadFile(String fileName) throws IOException {
    Path filePath = Paths.get(fileName);
    logger.info(SonatypeConstants.MSG_DLT_FILE + fileName);
    Files.delete(filePath);
  }

  private void backupLoadFile(String fileName, String iqProject, String iqPhase, String loadLocation) {
    try {
      String timeStamp = Long.toString(new Date().getTime());
      File loadFile = new File(fileName);
      if (loadFile.renameTo(new File(loadLocation + iqProject + "_" + iqPhase + "_" + timeStamp + "_" +
          "backup.json"))) {
        logger.info(SonatypeConstants.MSG_BKP_FILE + loadFile.getName());
      }
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_BKP_FILE + e.getMessage());
    }
  }
}
