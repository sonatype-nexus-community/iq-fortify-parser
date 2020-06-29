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
import java.io.FileWriter;
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
import com.sonatype.ssc.intsvc.model.IQProjectData;
import com.sonatype.ssc.intsvc.model.IQProjectVulnerability;
import com.sonatype.ssc.intsvc.model.IQSSCMapping;
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

  private static final String CONT_SRC = "source";

  private static final String CONT_DESC = "description";

  private static final String CONT_CWECWE = "cwecwe";

  private static final String CONT_CVSS2 = "cvecvss2";

  private static final String CONT_CVSS3 = "cvecvss3";

  private static final String CONT_CWEURL = "cweurl";

  private static final String CONT_PACK_URL = "packageUrl";

  private static final String CONT_ST_CVSS3 = "sonatypecvss3";

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
      // get data from IQ then save to JSON
      String iqDataFile = getIQVulnerabilityData(iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp);

      if (iqDataFile != null && iqDataFile.length() > 0) {
        logger.info(SonatypeConstants.MSG_IQ_DATA_WRT + iqDataFile);

        // save data to SSC
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

    if (internalAppId == null || internalAppId.length() == 0) {
      logger.info(SonatypeConstants.MSG_NO_IQ_PRJ_1 + project + SonatypeConstants.MSG_NO_IQ_PRJ_2 + version
          + SonatypeConstants.MSG_NO_IQ_PRJ_3);
      return fileName;
    }

    IQProjectData iqProjectData = iqClient.getIQProjectData(internalAppId, version, project);

    if (iqProjectData.getProjectReportURL() == null || iqProjectData.getProjectReportURL().length() == 0) {
      logger.info(SonatypeConstants.MSG_NO_REP_1 + project + SonatypeConstants.MSG_NO_REP_2 + version
          + SonatypeConstants.MSG_NO_REP_3);
      return fileName;
    }

    if (!isNewLoad(project, version, appProp, iqProjectData)) {
      logger.info(SonatypeConstants.MSG_EVL_SCAN_SAME_1 + project + SonatypeConstants.MSG_EVL_SCAN_SAME_2
          + version + SonatypeConstants.MSG_EVL_SCAN_SAME_3);
    }

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
      fileName = saveIqDataAsJSON(iqProjectData, finalProjectVulMap, appProp.getIqServer(), appProp.getLoadLocation());

    } catch (Exception e) {
      logger.error("policyViolationResponse: " + e.getMessage());
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
    File prevFile = new File(appProp.getLoadLocation() + getJsonFilename(project, version));
    if (prevFile.exists()) {
      try {
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(new FileReader(prevFile));
        String scanDate = (String) json.get("scanDate");
        if (scanDate.equals(iqProjectData.getEvaluationDate())) {
          isNewLoad = false;
        }
      }
      catch (Exception e) {
        logger.error(SonatypeConstants.ERR_GET_IQ_DATA + e.getMessage());
      }
    }
    return isNewLoad;
  }

  private int countFindings(String project, String stage, ApplicationProperties appProp) {
    File prevFile = new File(appProp.getLoadLocation() + getJsonFilename(project, stage));
    logger.debug("looking for previous findings in " + prevFile);
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
        if (sscClient.uploadVulnerabilityByProjectVersion(sscAppId, new File(iqDataFile))) {
          logger.info("Data successfully uploaded into SSC application " + iqSscMapping.getSscApplication()
              + " version " + iqSscMapping.getSscApplicationVersion() + ", id=" + sscAppId);
        }
        else {
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

  @SuppressWarnings("unchecked")
  private String saveIqDataAsJSON(IQProjectData iqPrjData,
                           List<IQProjectVulnerability> iqPrjVul,
                           String iqServerURL,
                           String loadLocation)
  {
    logger.debug("Preparing IQ Data to save as JSON");
    JSONObject json = new JSONObject();
    json.put("engineVersion", "1.0");
    json.put("scanDate", iqPrjData.getEvaluationDate());
    json.put("buildServer", iqPrjData.getProjectName());
    json.put("numberOfFiles", iqPrjData.getTotalComponentCount());

    JSONArray list = new JSONArray();
    Iterator<IQProjectVulnerability> iterator = iqPrjVul.iterator();

    while (iterator.hasNext()) {
      IQProjectVulnerability iqProjectVul = iterator.next();

      JSONObject vul = new JSONObject();
      vul.put("uniqueId", iqProjectVul.getUniqueId());
      vul.put("issue", iqProjectVul.getIssue());
      vul.put("category", "Vulnerable OSS");
      vul.put("identificationSource", StringUtils.defaultString(iqProjectVul.getIdentificationSource()));
      vul.put("cveurl", StringUtils.defaultString(iqProjectVul.getCveurl()));
      vul.put("reportUrl", String.format("%s%s", iqServerURL, iqPrjData.getProjectIQReportURL()));
      vul.put("group", iqProjectVul.getGroup());
      vul.put("sonatypeThreatLevel", iqProjectVul.getSonatypeThreatLevel());

      if (iqProjectVul.getName() != null && !iqProjectVul.getName().isEmpty()) {
        vul.put("artifact", iqProjectVul.getName());
      }
      else {
        vul.put("artifact", iqProjectVul.getArtifact());
      }
      vul.put("version", StringUtils.defaultString(iqProjectVul.getVersion()));
      vul.put("fileName", StringUtils.defaultString(iqProjectVul.getFileName()));
      vul.put("matchState", StringUtils.defaultString(iqProjectVul.getMatchState()));

      vul.put("priority", StringUtils.defaultString(getPriority(iqProjectVul.getSonatypeThreatLevel())));
      vul.put("customStatus", StringUtils.defaultString(iqProjectVul.getCustomStatus()));
      vul.put("classifier", StringUtils.defaultString(iqProjectVul.getClassifier()));
      vul.put(CONT_PACK_URL, StringUtils.defaultString(iqProjectVul.getPackageUrl()));

      try {
        VulnDetailResponse vulnDetail = iqProjectVul.getVulnDetail();
        if (vulnDetail != null) {
          vul.put(CONT_SRC,
              StringUtils.defaultIfBlank(vulnDetail.getSource().getLongName(), "N/A"));

          String combinedDesc = buildDescription(vulnDetail, iqProjectVul);
          vul.put("vulnerabilityAbstract",
              StringUtils.defaultIfBlank(combinedDesc, "N/A"));

          vul.put(CONT_DESC,
              StringUtils.defaultIfBlank(combinedDesc, "N/A"));

          if (vulnDetail.getWeakness() != null && !vulnDetail.getWeakness().getCweIds().isEmpty()) {
            vul.put(CONT_CWECWE,
                StringUtils.defaultIfBlank(vulnDetail.getWeakness().getCweIds().get(0).getId(), "N/A"));
            vul.put(CONT_CWEURL,
                StringUtils.defaultIfBlank(vulnDetail.getWeakness().getCweIds().get(0).getUri(), "N/A"));
          }

          if (vulnDetail.getSeverityScores() != null && !vulnDetail.getSeverityScores().isEmpty()) {
              vul.put(CONT_CVSS2,
                  StringUtils.defaultIfBlank(vulnDetail.getSeverityScores().get(0).getScore().toString(), "N/A"));
            if (vulnDetail.getSeverityScores().size() > 1) {
              vul.put(CONT_CVSS3,
                  StringUtils.defaultIfBlank(vulnDetail.getSeverityScores().get(1).getScore().toString(), "N/A"));
            }
          }

          if (vulnDetail.getMainSeverity() != null) {
            vul.put(CONT_ST_CVSS3,
                StringUtils.defaultIfBlank(vulnDetail.getMainSeverity().getScore().toString(), "N/A"));
          }
        }
        else {
          vul.put("vulnerabilityAbstract", "Vulnerability detail not available.");
        }
      } catch (Exception e) {
        logger.error(iqProjectVul.getIssue() + " - getVulnDetail: " + e.getMessage());
      }
        list.add(vul);
    }

    json.put("findings", list);
    return writeJsonToFile(iqPrjData, loadLocation, json);
  }

  private String buildDescription(VulnDetailResponse vulnDetail, IQProjectVulnerability iqProjectVul) {
    String desc = "";

    if (vulnDetail != null) {
      desc =  "<strong>Recommended Version(s): </strong>" +
              StringUtils.defaultString(parseRemediationResponse(iqProjectVul.getRemediationResponse(), iqProjectVul)) + "\r\n\r\n" +
              StringUtils.defaultString(vulnDetail.getDescription()) + "\r\n\r\n<strong>Explanation: </strong>" +
              StringUtils.defaultString(vulnDetail.getExplanationMarkdown()) + "\r\n\r\n<strong>Detection: </strong>" +
              StringUtils.defaultString(vulnDetail.getDetectionMarkdown()) + "\r\n\r\n<strong>Recommendation: </strong>" +
              StringUtils.defaultString(vulnDetail.getRecommendationMarkdown()) + "\r\n\r\n<strong>Threat Vectors: </strong>" +
              StringUtils.defaultString(vulnDetail.getMainSeverity().getVector());
    } else {
      desc = "Full description not available.";
    }
    return desc;

  }

  private String parseRemediationResponse(RemediationResponse response, IQProjectVulnerability iqProjectVul) {
    if (response.getRemediation().getVersionChanges() != null
        && !response.getRemediation().getVersionChanges().isEmpty()) {
      logger.debug(("*** getVersionChanges: ") + response.getRemediation().getVersionChanges().toString());
      logger.debug("*** Attempting to get Recommended Version: ");
      String recommendedVersion = response.getRemediation().getVersionChanges().get(0).getData().getComponent()
          .getComponentIdentifier().getCoordinates().getVersion();
      logger.debug("*** Recommended Version: " + recommendedVersion);
      logger.debug("*** Actual Version: " + iqProjectVul.getVersion());
      if (recommendedVersion.equalsIgnoreCase(iqProjectVul.getVersion())) {
        return "No recommended versions are available for the current component.";
      }
      return recommendedVersion;
    }

    return "No recommended versions are available for the current component.";
  }

  private String getPriority(String threatLevel) {
    int pPriority = Integer.parseInt(threatLevel);
    String mPriority = "";

    if (pPriority >= 8) {
      mPriority = "Critical";
    }
    else if (pPriority > 4 && pPriority < 8) {
      mPriority = "High";
    }
    else if (pPriority > 1 && pPriority < 4) {
      mPriority = "Medium";
    }
    else {
      mPriority = "Low";
    }
    return mPriority;
  }

  private static String getJsonFilename(String appId, String stage) {
    return appId + '_' + stage + ".json";
  }

  private String writeJsonToFile(final IQProjectData iqPrjData, final String loadLocation, final JSONObject json) {
    String filename = loadLocation + getJsonFilename(iqPrjData.getProjectName(), iqPrjData.getProjectStage());
    logger.debug(SonatypeConstants.MSG_WRITE_DATA + filename);

    try (FileWriter file = new FileWriter(filename)) {

      file.write(json.toJSONString());
      file.flush();
      return filename;
    }
    catch (IOException e) {
      logger.error(SonatypeConstants.ERR_WRITE_LOAD + e.getMessage());
      return "";
    }
  }

  private void deleteLoadFile(String fileName) throws IOException {
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
