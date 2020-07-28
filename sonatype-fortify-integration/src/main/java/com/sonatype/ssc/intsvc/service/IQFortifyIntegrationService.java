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

import static org.apache.commons.lang3.StringUtils.defaultString;
import static org.apache.commons.lang3.StringUtils.defaultIfBlank;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.springframework.stereotype.Service;

import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.SonatypeScan;
import com.sonatype.ssc.intsvc.model.SonatypeVuln;
import com.sonatype.ssc.intsvc.model.IQSSCMapping;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Component;
import com.sonatype.ssc.intsvc.model.PolicyViolation.ComponentIdentifier;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Coordinates;
import com.sonatype.ssc.intsvc.model.PolicyViolation.PolicyViolationResponse;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Violation;
import com.sonatype.ssc.intsvc.model.Remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.model.Remediation.VersionChange;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.CweId;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.MainSeverity;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.SeverityScore;
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
        saveMapping(appProp, iqSscMapping);
      }
    }
    logger.info(SonatypeConstants.MSG_DATA_CMP);
  }

  private boolean startLoadProcess(IQSSCMapping iqSscMapping, ApplicationProperties appProp) throws IOException {
    boolean success = false;
    if (verifyMapping(iqSscMapping)) {
      // get data from IQ then save to JSON
      File iqDataFile = getScanData(iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp);

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
   * Get IQ scan data on an IQ application in defined stage, then save extracted scan
   * data to a JSON file if there are new results (compared against last save).
   *
   * @param project the IQ public application id
   * @param stage   the IQ stage to look at
   * @param appProp the app configuration to access IQ
   * @return the JSON file containing extracted scan data from IQ (or null if any
   *         issue or new extraction got the same result that previous run)
   * @see #saveScanDataAsJSON(SonatypeScan, List, String, File)
   */
  private File getScanData(String project, String stage, ApplicationProperties appProp) {

    logger.debug(String.format(SonatypeConstants.MSG_READ_IQ, project, stage));
    IQClient iqClient = new IQClient(appProp);

    String internalAppId = iqClient.getInternalApplicationId(project);

    if (StringUtils.isBlank(internalAppId)) {
      logger.info(String.format(SonatypeConstants.MSG_NO_IQ_PRJ, project, stage));
      return null;
    }

    SonatypeScan scan = new SonatypeScan();
    scan.setProjectName(project);
    scan.setProjectStage(stage);
    scan.setInternalAppId(internalAppId);

    // get base Sonatype IQ scan data on report for application and stage
    iqClient.getReportInfo(scan);

    if (StringUtils.isBlank(scan.getProjectReportURL())) {
      logger.info(String.format(SonatypeConstants.MSG_NO_REP, project, stage));
      return null;
    }

    if (scan.getEvaluationDate().equals(getLastScanDate(project, stage, appProp.getLoadLocation()))) {
      // current report evaluation date is the same as last save: no new data
      logger.info(String.format(SonatypeConstants.MSG_EVL_SCAN_SAME, project, stage));
      return null;
    }

    try {
      // extract policy violations from IQ report
      PolicyViolationResponse policyViolationResponse = iqClient.getPolicyViolationsByReport(project,
          scan.getProjectReportId());

      // translate to vulns for SSC
      List<SonatypeVuln> vulns = translatePolicyViolationResults(policyViolationResponse, appProp, scan);

      // check if new vulns were found vs last save
      if (vulns.size() == countFindings(scan.getProjectName(), scan.getProjectStage(), appProp.getLoadLocation())) {
        logger.info(
            String.format(SonatypeConstants.MSG_FINDINGS_SAME_COUNT, scan.getProjectName(), scan.getProjectStage()));
        return null;
      }

      // ArrayList<ProjectVulnerability> finalProjectVulMap =
      // readVulData(iqPolicyReport, appProp, iqProjectData);

      scan.setTotalComponentCount(policyViolationResponse.getCounts().getTotalComponentCount());

      return saveScanDataAsJSON(scan, vulns, appProp.getLoadLocation());

    } catch (Exception e) {
      logger.error("getScanData(" + project + ", " + stage + "):" + e.getMessage(), e);
    }
    return null;
  }

  /**
   * Translate IQ Policy violation results into a list of vulnerabilities to send to SSC.
   * 
   * @param policyViolationResponse policy violations read from IQ
   * @param appProp integration service configuration
   * @param scan current scan
   * @return the list of vulnerabilities to be sent to SSC
   */
  private List<SonatypeVuln> translatePolicyViolationResults(PolicyViolationResponse policyViolationResponse,
      ApplicationProperties appProp, SonatypeScan scan) {

    IQClient iqClient = new IQClient(appProp);

    List<SonatypeVuln> vulnList = new ArrayList<>();
    final Pattern pattern = Pattern.compile("Found security vulnerability (.*) with");
    List<Component> components = policyViolationResponse.getComponents();

    for (Component component : components) {
      if (component.getViolations() != null) {
        for (Violation violation : component.getViolations()) {
          // ignore if the violation is waived, grand-fathered or is not a security category
          if (violation.getWaived() || violation.getGrandfathered()
              || !(violation.getPolicyThreatCategory().equalsIgnoreCase("SECURITY"))) {
            continue;
          }

          SonatypeVuln vuln = new SonatypeVuln();

          Matcher matcher = pattern
              .matcher(violation.getConstraints().get(0).getConditions().get(0).getConditionReason());
          if (matcher.find()) {
            String cve = matcher.group(1);
            logger.debug("CVE: " + cve + ", uniqueId: " + violation.getPolicyViolationId());
            vuln.setIssue(cve);
            vuln.setCveurl(defaultString(iqClient.getVulnDetailURL(cve)));

            vuln.setUniqueId(defaultString(violation.getPolicyViolationId()));
            vuln.setPackageUrl(defaultString(component.getPackageUrl()));
            vuln.setHash(defaultString(component.getHash()));

            ComponentIdentifier componentIdentifier = component.getComponentIdentifier();
            Coordinates coordinates = componentIdentifier.getCoordinates();
            if ("composer".equalsIgnoreCase(componentIdentifier.getFormat())) {
              String name = coordinates.getAdditionalProperties().get("name").toString();
              vuln.setFileName(defaultString(name));
              vuln.setFormat(defaultString(componentIdentifier.getFormat()));
              vuln.setName(defaultString(name));
              vuln.setGroup(defaultString(coordinates.getGroupId()));
              vuln.setVersion(defaultString(coordinates.getVersion()));
            } else {
              vuln.setFileName(defaultString(component.getPackageUrl()));
              vuln.setName(defaultString(coordinates.getArtifactId()));
              vuln.setFormat(defaultString(componentIdentifier.getFormat()));
              vuln.setArtifact(defaultString(coordinates.getArtifactId()));
              vuln.setClassifier(defaultString(coordinates.getClassifier()));
              vuln.setExtension(defaultString(coordinates.getExtension()));
              vuln.setGroup(defaultString(coordinates.getGroupId()));
              vuln.setVersion(defaultString(coordinates.getVersion()));
            }

//              iqPrjVul.setMatchState(defaultString(component.getMatchState()));

            vuln.setSonatypeThreatLevel(defaultString(violation.getPolicyThreatLevel().toString()));

            // load vuln details from IQ
            try {
              vuln.setVulnDetail(iqClient.getVulnDetails(cve));
            } catch (Exception e) {
              logger.error("vulnDetails(" + cve + "): " + e.getMessage(), e);
            }

            try {

              // load component details from IQ
              vuln.setCompReportDetails(iqClient.getComponentDetails(vuln.getPackageUrl()));

              // load component remediation from IQ
              RemediationResponse remediationResponse = iqClient.getCompRemediation(scan.getInternalAppId(),
                  scan.getProjectStage(), vuln.getPackageUrl());

              if (remediationResponse != null) {
                vuln.setRemediationResponse(remediationResponse);
              }
            } catch (Exception e) {
              logger.error("remediationResponse(" + vuln.getPackageUrl() + "): " + e.getMessage(), e);
            }

          }
          vulnList.add(vuln);
        }
      }
    }

    return vulnList;
  }

  private int countFindings(String project, String stage, File loadLocation) {
    JSONObject json = loadPrevious(project, stage, loadLocation);
    if (json == null) {
      // no previous scan
      return -1;
    }

    JSONArray findings = (JSONArray) json.get("findings");
    return findings.size();
  }

  private boolean loadDataIntoSSC(IQSSCMapping iqSscMapping, ApplicationProperties appProp, File scanDataFile)
      throws IOException
  {
    SSCClient sscClient = new SSCClient(appProp);
    boolean success = true;
    long sscAppId = sscClient.getSSCApplicationId(iqSscMapping.getSscApplication(), iqSscMapping.getSscApplicationVersion());
    if (sscAppId == 0) {
      sscAppId = sscClient.getNewSSCApplicationId(iqSscMapping.getSscApplication(), iqSscMapping.getSscApplicationVersion());
    }

    logger.debug("SSC Application id: " + sscAppId);
    if (sscAppId > 0) {
      try {
        if (sscClient.uploadVulnerabilityByProjectVersion(sscAppId, scanDataFile)) {
          logger.info("Data successfully uploaded into SSC application " + iqSscMapping.getSscApplication()
              + " version " + iqSscMapping.getSscApplicationVersion() + ", id=" + sscAppId);
        }
        else {
          backupLoadFile(scanDataFile, iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp.getLoadLocation());
          success = false;
        }
      }
      catch (Exception e) {
        success = false;
        logger.error(SonatypeConstants.ERR_SSC_APP_UPLOAD + e.getMessage(), e);
        backupLoadFile(scanDataFile, iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp.getLoadLocation());
      }
    }
    else if (sscAppId == -1) {
      deleteLoadFile(scanDataFile);
      success = false;
    }
    else {
      logger.error(SonatypeConstants.ERR_SSC_CREATE_APP);
      deleteLoadFile(scanDataFile);
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
        logger.error(SonatypeConstants.ERR_KILL_PRC + e.getMessage(), e);
        return "FAILED";
      }
    }
    else {
      try {
        Runtime.getRuntime().exec("kill -9 " + pId);
        return "SUCCESS";
      }
      catch (IOException e) {
        logger.error(SonatypeConstants.ERR_KILL_PRC + e.getMessage(), e);
        return "FAILED";
      }
    }
  }

  @SuppressWarnings("unchecked")
  private File saveScanDataAsJSON(SonatypeScan scan, List<SonatypeVuln> vulns, File loadLocation) {
    JSONObject json = new JSONObject();
    json.put("engineVersion", "1.0");
    json.put("scanDate", scan.getEvaluationDate());
    json.put("buildServer", scan.getProjectName());
    json.put("numberOfFiles", scan.getTotalComponentCount());

    JSONArray list = new JSONArray();
    for (SonatypeVuln vuln : vulns) {

      JSONObject vul = new JSONObject();
      vul.put("uniqueId", vuln.getUniqueId());
      vul.put("issue", vuln.getIssue());
      vul.put("category", "Vulnerable OSS");
      vul.put("identificationSource", defaultString(vuln.getIdentificationSource()));
      vul.put("cveurl", defaultString(vuln.getCveurl()));
      vul.put("reportUrl", scan.getProjectIQReportURL());
      vul.put("group", vuln.getGroup());
      vul.put("sonatypeThreatLevel", vuln.getSonatypeThreatLevel());

      if (StringUtils.isNotEmpty(vuln.getName())) {
        vul.put("artifact", vuln.getName());
      }
      else {
        vul.put("artifact", vuln.getArtifact());
      }
      vul.put("version", defaultString(vuln.getVersion()));
      vul.put("fileName", defaultString(vuln.getFileName()));
      vul.put("matchState", defaultString(vuln.getMatchState()));

      vul.put("priority", defaultString(translateThreatLevelToPriority(vuln.getSonatypeThreatLevel())));
      vul.put("customStatus", defaultString(vuln.getCustomStatus()));
      vul.put("classifier", defaultString(vuln.getClassifier()));
      vul.put(CONT_PACK_URL, defaultString(vuln.getPackageUrl()));

      try {
        VulnDetailResponse vulnDetail = vuln.getVulnDetail();
        if (vulnDetail != null) {
          vul.put(CONT_SRC, defaultIfBlank(vulnDetail.getSource().getLongName(), "N/A"));

          String combinedDesc = buildDescription(vulnDetail, vuln);
          vul.put("vulnerabilityAbstract", defaultIfBlank(combinedDesc, "N/A"));

          vul.put(CONT_DESC, defaultIfBlank(combinedDesc, "N/A"));

          if (vulnDetail.getWeakness() != null) {
            List<CweId> cweIds = vulnDetail.getWeakness().getCweIds();
            if (!cweIds.isEmpty()) {
              CweId cweId = cweIds.get(0);
              vul.put(CONT_CWECWE, defaultIfBlank(cweId.getId(), "N/A"));
              vul.put(CONT_CWEURL, defaultIfBlank(cweId.getUri(), "N/A"));
            }
          }

          List<SeverityScore> severityScores = vulnDetail.getSeverityScores();
          if (severityScores != null && !severityScores.isEmpty()) {
            vul.put(CONT_CVSS2, defaultIfBlank(severityScores.get(0).getScore().toString(), "N/A"));
            if (severityScores.size() > 1) {
              vul.put(CONT_CVSS3, defaultIfBlank(severityScores.get(1).getScore().toString(), "N/A"));
            }
          }

          MainSeverity mainSeverity = vulnDetail.getMainSeverity();
          if (mainSeverity != null) {
            vul.put(CONT_ST_CVSS3, defaultIfBlank(mainSeverity.getScore().toString(), "N/A"));
          }
        }
        else {
          vul.put("vulnerabilityAbstract", "Vulnerability detail not available.");
        }
      } catch (Exception e) {
        logger.error(vuln.getIssue() + " - getVulnDetail: " + e.getMessage(), e);
      }

      list.add(vul);
    }

    json.put("findings", list);
    return writeJsonToFile(scan, loadLocation, json);
  }

  private String buildDescription(VulnDetailResponse vulnDetail, SonatypeVuln vuln) {
    String desc = "";

    if (vulnDetail != null) {
      desc = "<strong>Recommended Version(s): </strong>" + defaultString(describeRemediationResponse(vuln)) + "\r\n\r\n"
          + defaultString(vulnDetail.getDescription()) + "\r\n\r\n"
          + "<strong>Explanation: </strong>" + defaultString(vulnDetail.getExplanationMarkdown()) + "\r\n\r\n"
          + "<strong>Detection: </strong>" + defaultString(vulnDetail.getDetectionMarkdown()) + "\r\n\r\n"
          + "<strong>Recommendation: </strong>" + defaultString(vulnDetail.getRecommendationMarkdown()) + "\r\n\r\n"
          + "<strong>Threat Vectors: </strong>" + defaultString(vulnDetail.getMainSeverity().getVector());
    } else {
      desc = "Full description not available.";
    }
    return desc;

  }

  private String describeRemediationResponse(SonatypeVuln vuln) {
    List<VersionChange> versionChanges = vuln.getRemediationResponse().getRemediation().getVersionChanges();

    if (versionChanges != null && !versionChanges.isEmpty()) {
      String recommendedVersion = versionChanges.get(0).getData().getComponent().getComponentIdentifier()
          .getCoordinates().getVersion();
      if (recommendedVersion.equalsIgnoreCase(vuln.getVersion())) {
        return "No recommended versions are available for the current component.";
      }
      return recommendedVersion;
    }

    return "No recommended versions are available for the current component.";
  }

  private String translateThreatLevelToPriority(String threatLevel) {
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
    return appId + '_' + stage + (backup ? ("_" + System.currentTimeMillis() + "_backup") : "") + ".json";
  }

  private File writeJsonToFile(final SonatypeScan scan, final File loadLocation, final JSONObject json) {
    File file = new File(loadLocation, getJsonFilename(scan.getProjectName(), scan.getProjectStage()));
    logger.debug(SonatypeConstants.MSG_WRITE_DATA + file);

    try (FileWriter w = new FileWriter(file)) {
      w.write(json.toJSONString());
      return file;
    } catch (IOException e) {
      logger.error(SonatypeConstants.ERR_WRITE_LOAD + e.getMessage());
    }
    return null;
  }

  private JSONObject loadPrevious(String project, String stage, File loadLocation) {
    File prevFile = new File(loadLocation, getJsonFilename(project, stage));
    if (prevFile.exists()) {
      try {
        JSONParser parser = new JSONParser();
        return (JSONObject) parser.parse(new FileReader(prevFile));
      }
      catch (Exception e) {
        logger.error("Could not read save file: " + prevFile + ": " + e.getMessage(), e);
      }
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
    } catch (Exception e) {
      logger.error(SonatypeConstants.ERR_BKP_FILE + e.getMessage());
    }
  }

  private void saveMapping(ApplicationProperties appProp, IQSSCMapping iqSscMapping) {
    File mappingFile = appProp.getMapFile();
    if (mappingFile == null) {
      logger.error("No mapping file configured, cannot save new mapping");
      return;
    }
    if (!mappingFile.exists()) {
      logger.error("Mapping file " + mappingFile + " does not exist, cannot save new mapping");
      return;
    }
    List<IQSSCMapping> mappings = loadMapping(appProp);
    for (IQSSCMapping applicationMapping : mappings) {
      if (applicationMapping.equals(iqSscMapping)) {
        logger.info("Mapping already available in configuration, not saving.");
        return;
      }
    }

    // effective save
    File newMappingFile = new File(mappingFile.getParentFile(), mappingFile.getName() + ".new");
    try {
      String mapping = FileUtils.readFileToString(mappingFile, "UTF-8");
      int index = mapping.lastIndexOf('}') + 1;
      if (index == 0) {
        // first mapping
        mapping = "[" + System.lineSeparator() + iqSscMapping.toJson() + System.lineSeparator() + "]";
      }
      else {
        // append a mapping
        mapping = mapping.substring(0, index) + ',' + System.lineSeparator() + iqSscMapping.toJson() + mapping.substring(index);
      }
      FileUtils.write(newMappingFile, mapping, "UTF-8");

      File oldMappingFile = new File(mappingFile.getParentFile(), mappingFile.getName() + ".old");
      if (oldMappingFile.exists() && !oldMappingFile.delete()) {
        logger.error("could not delete old " + oldMappingFile);
      }
      else if (!mappingFile.renameTo(oldMappingFile)) {
        logger.error("could not save " + mapping + " by renaming to " + oldMappingFile);
      }
      else if (!newMappingFile.renameTo(mappingFile)) {
        logger.error("could not rename new " + newMappingFile + " to " + mappingFile);
      }
      else {
        logger.info("New mapping added to " + mappingFile);
      }
    } catch (IOException e) {
      logger.error("error while reading/writing mapping file", e);
    }
  }

  private String getLastScanDate(String project, String stage, File loadLocation) {
    JSONObject json = loadPrevious(project, stage, loadLocation);
    if (json != null) {
      return (String) json.get("scanDate");
    }
    return null;
  }
}
