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
import java.util.ArrayList;
import java.util.List;
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
import com.sonatype.ssc.intsvc.model.ProjectVulnerability;
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
    List<IQSSCMapping> mappings = loadMapping(appProp);
    if (mappings != null) {
      for (IQSSCMapping applicationMapping : mappings) {
        totalCount++;
        if (startLoadProcess(applicationMapping, appProp)) {
          successCount++;
        }
      }
    }
    logger.info(SonatypeConstants.MSG_DATA_CMP);
    logger.info(SonatypeConstants.MSG_TOT_CNT + totalCount);
    logger.info(SonatypeConstants.MSG_IQ_CNT + successCount + " projects");
  }

  public void startLoad(ApplicationProperties appProp, IQSSCMapping iqSscMapping, boolean saveMapping)
      throws IOException {
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
      File iqDataFile = getIQVulnerabilityData(iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp);

      if (iqDataFile != null) {
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

    if (StringUtils.isBlank(iqProject)) {
      logger.error(SonatypeConstants.ERR_IQ_PRJ);
      success = false;
    }
    if (StringUtils.isBlank(iqPhase)) {
      logger.error(SonatypeConstants.ERR_IQ_PRJ_STG);
      success = false;
    }
    if (StringUtils.isBlank(sscAppName)) {
      logger.error(SonatypeConstants.ERR_SSC_APP);
      success = false;
    }
    if (StringUtils.isBlank(sscAppVersion)) {
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

  /**
   * Get IQ data on an IQ application in defined stage, then save extracted data to a JSON file.
   *
   * @param project the IQ public application id
   * @param stage the IQ stage to look at
   * @param appProp the app configuration to access IQ
   * @return the JSON file containing extracted data from IQ (or null if any issue)
   * @see #saveIqDataAsJSON(IQProjectData, List, String, File)
   */
  private File getIQVulnerabilityData(String project, String stage, ApplicationProperties appProp) {

    logger.debug(String.format(SonatypeConstants.MSG_READ_IQ, project, stage));
    IQClient iqClient = new IQClient(appProp);

    String internalAppId = iqClient.getInternalApplicationId(project);
    logger.debug("Got internal application id from IQ: " + internalAppId + " for " + project);

    if (StringUtils.isBlank(internalAppId)) {
      logger.info(String.format(SonatypeConstants.MSG_NO_IQ_PRJ, project, stage));
      return null;
    }

    IQProjectData iqProjectData = iqClient.getIQProjectData(internalAppId, stage, project);

    if (StringUtils.isBlank(iqProjectData.getProjectReportURL()) {
      logger.info(String.format(SonatypeConstants.MSG_NO_REP, project, stage));
      return null;
    }

    if (!isNewLoad(project, stage, appProp.getLoadLocation(), iqProjectData)) {
      logger.info(String.format(SonatypeConstants.MSG_EVL_SCAN_SAME, project, stage));
    }

    //TODO: Get the policy based report here.
    String iqPolicyReportResults = iqClient.getPolicyReport(project, iqProjectData.getProjectReportId());
    logger.debug("** In getIQVulnerabilityData.  iqPolicyReportResults: " + iqPolicyReportResults);

    //TODO: Parse the results of the policy violation report
    try {
      PolicyViolationResponse policyViolationResponse = (new ObjectMapper()).readValue(iqPolicyReportResults,
          PolicyViolationResponse.class);
      logger.debug("** Finding Current Count: " + countFindings(project, stage, appProp.getLoadLocation()));

      logger.debug("** before translatePolicyViolationResults");
      List<ProjectVulnerability> vulnList = translatePolicyViolationResults(policyViolationResponse, appProp,
          iqProjectData);
      if (vulnList == null) {
          return null;
      }

      // ArrayList<ProjectVulnerability> finalProjectVulMap =
      // readVulData(iqPolicyReport, appProp, iqProjectData);

      iqProjectData.setTotalComponentCount(policyViolationResponse.getCounts().getTotalComponentCount());

      String projectIQReportURL = iqClient.getIqReportUrl(iqProjectData.getProjectName(),
          iqProjectData.getProjectReportId(), appProp.getIqReportType());
      iqProjectData.setProjectIQReportURL(projectIQReportURL);

      logger.debug("** before saveIqDataAsJSON: " + iqProjectData.toString());
      return saveIqDataAsJSON(iqProjectData, vulnList, appProp.getIqServer(), appProp.getLoadLocation());

    } catch (Exception e) {
      logger.error("policyViolationResponse: " + e.getMessage());
    }
    return null;
  }

  /**
   * Translate IQ Policy violation results into a list of vulnerabilities to send to SSC.
   * 
   * @param policyViolationResponse policy violations read from IQ
   * @param appProp integration service configuration
   * @param iqProjectData current project data
   * @return the list of vulnerabilities to be sent to SSC
   */
  private List<ProjectVulnerability> translatePolicyViolationResults(PolicyViolationResponse policyViolationResponse,
      ApplicationProperties appProp, IQProjectData iqProjectData) {

    logger.debug("** In parsePolicyViolationResults");
    IQClient iqClient = new IQClient(appProp);

    List<ProjectVulnerability> vulnList = new ArrayList<>();
    final Pattern pattern = Pattern.compile("Found security vulnerability (.*) with");
    List<Component> components = policyViolationResponse.getComponents();

    for (Component component : components) {
      logger.debug("** component hash: " + component.getHash());
      if (component.getViolations() != null && component.getViolations().size() > 0) {
        for (Violation violation : component.getViolations()) {
          // If the violation is waived and is not a security category
          if (violation.getWaived() || violation.getGrandfathered()
              || !(violation.getPolicyThreatCategory().equalsIgnoreCase("SECURITY"))) {
            continue;
          }

          ProjectVulnerability prjVul = new ProjectVulnerability();

          logger.debug(
              "** condition reason: " + violation.getConstraints().get(0).getConditions().get(0).getConditionReason());
          Matcher matcher = pattern
              .matcher(violation.getConstraints().get(0).getConditions().get(0).getConditionReason());
          if (matcher.find()) {
            String CVE = matcher.group(1);
            logger.debug("CVE: " + CVE);
            prjVul.setIssue(CVE);
            prjVul.setCveurl(StringUtils.defaultString(iqClient.getVulnDetailURL(CVE, appProp)));

            prjVul.setUniqueId(StringUtils.defaultString(violation.getPolicyViolationId()));
            prjVul.setPackageUrl(StringUtils.defaultString(component.getPackageUrl()));
            prjVul.setHash(StringUtils.defaultString(component.getHash()));
            if (component.getComponentIdentifier().getFormat().equalsIgnoreCase("composer")) {
              logger.debug("Component Identifier is composer: " + component.getComponentIdentifier().toString());
              prjVul.setFileName(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates()
                  .getAdditionalProperties().get("name").toString()));
              prjVul.setFormat(StringUtils.defaultString(component.getComponentIdentifier().getFormat()));
              prjVul.setName(StringUtils.defaultString(component.getComponentIdentifier().getCoordinates()
                  .getAdditionalProperties().get("name").toString()));
              prjVul.setGroup(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getGroupId()));
              logger.debug("******** NAME: " + StringUtils.defaultString(component.getComponentIdentifier()
                  .getCoordinates().getAdditionalProperties().get("name").toString()));
              prjVul.setVersion(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getVersion()));
            } else {
              prjVul.setFileName(StringUtils.defaultString(component.getPackageUrl()));

              prjVul.setName(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getArtifactId()));
              prjVul.setFormat(StringUtils.defaultString(component.getComponentIdentifier().getFormat()));
              prjVul.setArtifact(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getArtifactId()));
              prjVul.setClassifier(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getClassifier()));
              prjVul.setExtension(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getExtension()));
              prjVul.setGroup(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getGroupId()));
              prjVul.setVersion(
                  StringUtils.defaultString(component.getComponentIdentifier().getCoordinates().getVersion()));
            }

//              iqPrjVul.setMatchState(StringUtils.defaultString(component.getMatchState()));

            prjVul.setSonatypeThreatLevel(StringUtils.defaultString(violation.getPolicyThreatLevel().toString()));

            // load vuln details from IQ
            String strResponseVulnDetails = iqClient.getVulnDetail(CVE, appProp);

            if (strResponseVulnDetails.equalsIgnoreCase("UNKNOWN")) {
              // Don't parse the vuln details if we don't have
              prjVul.setVulnDetail(null);
            } else {
              try {
                VulnDetailResponse vulnDetailResponse = (new ObjectMapper()).readValue(strResponseVulnDetails,
                    VulnDetailResponse.class);
                if (vulnDetailResponse != null) {
                  prjVul.setVulnDetail(vulnDetailResponse);
                }
              } catch (Exception e) {
                logger.error("vulDetailRest: " + e.getMessage());
              }
            }

            try {

              // load component details from IQ
              prjVul.setCompReportDetails(iqClient.getComponentDetails(prjVul.getPackageUrl()));

              // load component remediation from IQ
              String componentRemediationResults = iqClient.getCompRemediation(iqProjectData, prjVul.getPackageUrl());

              RemediationResponse remediationResponse = (new ObjectMapper()).readValue(componentRemediationResults,
                  RemediationResponse.class);

              if (remediationResponse != null) {
                prjVul.setRemediationResponse(remediationResponse);
                logger.debug("** Setting remediation response for vulnerability details.");
              }
            } catch (Exception e) {
              logger.error("remediationResponse: " + e.getMessage());
            }

          }
          vulnList.add(prjVul);
        }
      }
    }
    logger.debug("finalProjectVulMap.size(): " + vulnList.size());
    if (vulnList.size() == countFindings(iqProjectData.getProjectName(), iqProjectData.getProjectStage(),
        appProp.getLoadLocation())) {
      logger.info(String.format(SonatypeConstants.MSG_FINDINGS_SAME_COUNT, iqProjectData.getProjectName(),
          iqProjectData.getProjectStage()));
      return null;
    }
    return vulnList;
  }

  private boolean isNewLoad(String project, String version, File loadLocation, IQProjectData iqProjectData) {
    boolean isNewLoad = true;
    File prevFile = new File(loadLocation, getJsonFilename(project, version));
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

  private int countFindings(String project, String stage, File loadLocation) {
    File prevFile = new File(loadLocation, getJsonFilename(project, stage));
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

  private boolean loadDataIntoSSC(IQSSCMapping iqSscMapping, ApplicationProperties appProp, File iqDataFile)
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
        if (sscClient.uploadVulnerabilityByProjectVersion(sscAppId, iqDataFile)) {
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
  private File saveIqDataAsJSON(IQProjectData iqPrjData,
                           List<ProjectVulnerability> prjVulns,
                           String iqServerURL,
                           File loadLocation)
  {
    logger.debug("Preparing IQ Data to save as JSON");
    JSONObject json = new JSONObject();
    json.put("engineVersion", "1.0");
    json.put("scanDate", iqPrjData.getEvaluationDate());
    json.put("buildServer", iqPrjData.getProjectName());
    json.put("numberOfFiles", iqPrjData.getTotalComponentCount());

    JSONArray list = new JSONArray();
    for ( ProjectVulnerability projectVul : prjVulns) {

      JSONObject vul = new JSONObject();
      vul.put("uniqueId", projectVul.getUniqueId());
      vul.put("issue", projectVul.getIssue());
      vul.put("category", "Vulnerable OSS");
      vul.put("identificationSource", StringUtils.defaultString(projectVul.getIdentificationSource()));
      vul.put("cveurl", StringUtils.defaultString(projectVul.getCveurl()));
      vul.put("reportUrl", String.format("%s%s", iqServerURL, iqPrjData.getProjectIQReportURL()));
      vul.put("group", projectVul.getGroup());
      vul.put("sonatypeThreatLevel", projectVul.getSonatypeThreatLevel());

      if (projectVul.getName() != null && !projectVul.getName().isEmpty()) {
        vul.put("artifact", projectVul.getName());
      }
      else {
        vul.put("artifact", projectVul.getArtifact());
      }
      vul.put("version", StringUtils.defaultString(projectVul.getVersion()));
      vul.put("fileName", StringUtils.defaultString(projectVul.getFileName()));
      vul.put("matchState", StringUtils.defaultString(projectVul.getMatchState()));

      vul.put("priority", StringUtils.defaultString(getPriority(projectVul.getSonatypeThreatLevel())));
      vul.put("customStatus", StringUtils.defaultString(projectVul.getCustomStatus()));
      vul.put("classifier", StringUtils.defaultString(projectVul.getClassifier()));
      vul.put(CONT_PACK_URL, StringUtils.defaultString(projectVul.getPackageUrl()));

      try {
        VulnDetailResponse vulnDetail = projectVul.getVulnDetail();
        if (vulnDetail != null) {
          vul.put(CONT_SRC,
              StringUtils.defaultIfBlank(vulnDetail.getSource().getLongName(), "N/A"));

          String combinedDesc = buildDescription(vulnDetail, projectVul);
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
        logger.error(projectVul.getIssue() + " - getVulnDetail: " + e.getMessage());
      }
        list.add(vul);
    }

    json.put("findings", list);
    return writeJsonToFile(iqPrjData, loadLocation, json);
  }

  private String buildDescription(VulnDetailResponse vulnDetail, ProjectVulnerability projectVul) {
    String desc = "";

    if (vulnDetail != null) {
      desc =  "<strong>Recommended Version(s): </strong>" +
              StringUtils.defaultString(parseRemediationResponse(projectVul.getRemediationResponse(), projectVul)) + "\r\n\r\n" +
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

  private String parseRemediationResponse(RemediationResponse response, ProjectVulnerability projectVul) {
    if (response.getRemediation().getVersionChanges() != null
        && !response.getRemediation().getVersionChanges().isEmpty()) {
      logger.debug(("*** getVersionChanges: ") + response.getRemediation().getVersionChanges().toString());
      logger.debug("*** Attempting to get Recommended Version: ");
      String recommendedVersion = response.getRemediation().getVersionChanges().get(0).getData().getComponent()
          .getComponentIdentifier().getCoordinates().getVersion();
      logger.debug("*** Recommended Version: " + recommendedVersion);
      logger.debug("*** Actual Version: " + projectVul.getVersion());
      if (recommendedVersion.equalsIgnoreCase(projectVul.getVersion())) {
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
    return getJsonFilename(appId, stage, false);
  }

  private static String getJsonFilename(String appId, String stage, boolean backup) {
    return appId + '_' + stage + (backup ? ("_" + System.currentTimeMillis() + "_backup"): "") + ".json";
  }

  private File writeJsonToFile(final IQProjectData iqPrjData, final File loadLocation, final JSONObject json) {
    File file = new File(loadLocation, getJsonFilename(iqPrjData.getProjectName(), iqPrjData.getProjectStage()));
    logger.debug(SonatypeConstants.MSG_WRITE_DATA + file);

    try (FileWriter w = new FileWriter(file)) {
      w.write(json.toJSONString());
      return file;
    }
    catch (IOException e) {
      logger.error(SonatypeConstants.ERR_WRITE_LOAD + e.getMessage());
    }
    return null;
  }

  private void deleteLoadFile(File file) throws IOException {
    logger.info(SonatypeConstants.MSG_DLT_FILE + file);
    file.delete();
  }

  private void backupLoadFile(File loadFile, String iqProject, String iqPhase, File loadLocation) {
    try {
      if (loadFile.renameTo(new File(loadLocation, getJsonFilename(iqProject, iqPhase, true)))) {
        logger.info(SonatypeConstants.MSG_BKP_FILE + loadFile.getName());
      }
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_BKP_FILE + e.getMessage());
    }
  }
}
