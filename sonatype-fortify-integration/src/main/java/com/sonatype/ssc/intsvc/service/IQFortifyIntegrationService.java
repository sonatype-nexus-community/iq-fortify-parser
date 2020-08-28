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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.IQSSCMapping;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.model.Scan;
import com.sonatype.ssc.model.Finding;
import com.sonatype.ssc.intsvc.model.IQReportData;
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
import com.sonatype.ssc.intsvc.model.scanhistory.Report;
import com.sonatype.ssc.intsvc.util.IQClient;
import com.sonatype.ssc.intsvc.util.SSCClient;

@Service
public class IQFortifyIntegrationService
{
  private static final Logger logger = Logger.getRootLogger();

  public void startLoad(ApplicationProperties appProp) throws IOException {
    int totalCount = 0;
    int successCount = 0;
    List<IQSSCMapping> mappings = loadMapping(appProp);
    if (mappings != null) {
      for (IQSSCMapping applicationMapping : mappings) {
        totalCount++;
        if (executeProcess(applicationMapping, appProp)) {
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
    if (executeProcess(iqSscMapping, appProp)) {
      if (saveMapping) {
        saveMapping(appProp, iqSscMapping);
      }
    }
    logger.info(SonatypeConstants.MSG_DATA_CMP);
  }

  private boolean executeProcess(IQSSCMapping iqSscMapping, ApplicationProperties appProp) throws IOException {
    if (!iqSscMapping.verifyMapping(logger)) {
      return false;
    }

    // get data from IQ then save to JSON
    File iqDataFile = extractIQScanData(iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp);

    if (iqDataFile == null) {
      return false;
    }

    logger.info(SonatypeConstants.MSG_IQ_DATA_WRT + iqDataFile);

    // save data to SSC
    return loadDataIntoSSC(iqSscMapping, appProp, iqDataFile);
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
  private File extractIQScanData(String project, String stage, ApplicationProperties appProp) {

    logger.debug(String.format(SonatypeConstants.MSG_READ_IQ, project, stage));
    IQClient iqClient = new IQClient(appProp);

    String internalAppId = iqClient.getInternalApplicationId(project);

    if (StringUtils.isBlank(internalAppId)) {
      logger.info(String.format(SonatypeConstants.MSG_NO_IQ_PRJ, project, stage));
      return null;
    }

    // get base Sonatype IQ scan data on report for application and stage
    logger.info(SonatypeConstants.MSG_GET_IQ_DATA);
    IQReportData reportData = iqClient.getReportData(project, internalAppId, stage);

    if (reportData == null) {
      logger.info(String.format(SonatypeConstants.MSG_NO_REP, project, stage));
      return null;
    }

    Scan scan = new Scan();
    scan.setEngineVersion("1.0");
    scan.setScanDate(reportData.getEvaluationDate());
    scan.setBuildServer(project);

    if (scan.getScanDate().equals(getLastScanDate(project, stage, appProp.getLoadLocation()))) {
      // current report evaluation date is the same as last save: no new data
      logger.info(String.format(SonatypeConstants.MSG_EVL_SCAN_SAME, project, stage));
      return null;
    }

    // get data from scan history
    try {
      Report report = iqClient.getScanReportFromHistory(internalAppId, stage);
      if (report != null) {
        // store "new scan" vs "reevaluation" vs "continuous monitoring" in "build server" field (displayed in SSC artifact view)
        scan.setBuildServer(report.getIsForMonitoring() ? "isForMonitoring" : (report.getIsReevaluation() ? "isReevaluation" : "isNew"));
      }
    } catch (Exception e) {
      // optional data, don't fail: perhaps just an older IQ release
      logger.warn("getScanReportFromHistory(" + project + ", " + stage + "):" + e.getMessage(), e);
    }

    try {
      // extract policy violations from IQ report
      PolicyViolationResponse policyViolationResponse = iqClient.getPolicyViolationsByReport(project,
          reportData.getReportId());

      scan.setNumberOfFiles(policyViolationResponse.getCounts().getTotalComponentCount());

      // translate to findings for SSC
      List<Finding> vulns = translatePolicyViolationResults(policyViolationResponse, appProp, reportData);
      scan.setFindings(vulns);

      // check if new vulns were found vs last save
      if (checkSameFindings(project, stage, appProp, vulns)) {
        logger.info(String.format(SonatypeConstants.MSG_FINDINGS_SAME_COUNT, project, stage));
        return null;
      }

      return writeScanJsonToFile(scan, project, stage, appProp.getLoadLocation());

    } catch (Exception e) {
      logger.error("getScanData(" + project + ", " + stage + "):" + e.getMessage(), e);
    }
    return null;
  }

  /**
   * Translate IQ Policy violation results into a list of findings to send to SSC.
   * 
   * @param policyViolationResponse policy violations read from IQ
   * @param appProp integration service configuration
   * @param reportData current report data
   * @return the list of findings to be sent to SSC
   */
  private List<Finding> translatePolicyViolationResults(PolicyViolationResponse policyViolationResponse,
      ApplicationProperties appProp, IQReportData reportData) {

    IQClient iqClient = new IQClient(appProp);

    List<Finding> vulnList = new ArrayList<>();

    int componentsWithViolations = 0;
    int violations = 0;
    int waived = 0;
    int grandfathered = 0;
    Map<String, AtomicLong> threatCategories = new TreeMap<>();

    for (Component component : policyViolationResponse.getComponents()) {
      if (component.getViolations() == null || component.getViolations().size() == 0) {
        // no violation: skip component
        continue;
      }

      componentsWithViolations++;
      violations += component.getViolations().size();

      for (Violation violation : component.getViolations()) {
        // ignore if the violation is waived, grand-fathered
        if (violation.getWaived()) {
          waived++;
          continue;
        }
        if (violation.getGrandfathered()) {
          grandfathered++;
          continue;
        }

        // count violations per policy threat category
        String category = violation.getPolicyThreatCategory();
        threatCategories.computeIfAbsent(category, k -> new AtomicLong(0)).incrementAndGet();

        // ignore if the violation is not a security category
        if (!"SECURITY".equalsIgnoreCase(violation.getPolicyThreatCategory())) {
          continue;
        }

        // create 1 vuln/1 finding per violation that is not ignored
        Finding vuln = fromSecurityViolationToVuln(component, violation, iqClient, reportData);
        if (vuln != null) {
          vuln.setReportUrl(reportData.getReportUrl());
          vulnList.add(vuln);
        }
      }
    }

    logger.debug("summary: on " + policyViolationResponse.getComponents().size() + " components, "
        + componentsWithViolations + " had policy violations for " + violations + " violations: " + waived + " waived, "
        + grandfathered + " grandfathered, " + threatCategories);
    return vulnList;
  }

  private static final Pattern PATTERN = Pattern.compile("Found security vulnerability (.*) with");

  private Finding fromSecurityViolationToVuln(Component component, Violation violation, IQClient iqClient,
      IQReportData reportData) {
    // extract CVE id
    String reason = violation.getConstraints().get(0).getConditions().get(0).getConditionReason();
    Matcher matcher = PATTERN.matcher(reason);
    if (!matcher.find()) {
      logger.warn("Unexpected violation reason for " + violation.getPolicyViolationId() + ": " + reason);
      return null;
    }
    String cve = matcher.group(1);
    logger.debug("CVE: " + cve + ", uniqueId: " + violation.getPolicyViolationId());

    Finding vuln = new Finding();

    vuln.setCategory("Vulnerable OSS");
    vuln.setIssue(cve);
    vuln.setCveurl(defaultString(iqClient.getVulnDetailURL(cve)));

    vuln.setUniqueId(defaultString(violation.getPolicyViolationId()));
    //vuln.setHash(defaultString(component.getHash()));
    //vuln.setFormat(defaultString(componentIdentifier.getFormat()));

    ComponentIdentifier componentIdentifier = component.getComponentIdentifier();
    Coordinates coordinates = componentIdentifier.getCoordinates();
    vuln.setGroup(defaultString(coordinates.getGroupId()));
    vuln.setVersion(defaultString(coordinates.getVersion()));

    String name;
    if ("composer".equalsIgnoreCase(componentIdentifier.getFormat())) {
      name = coordinates.getAdditionalProperties().get("name").toString();
      vuln.setFileName(defaultString(name));
    } else {
      vuln.setFileName(defaultString(component.getPackageUrl()));
      name = coordinates.getArtifactId();
      vuln.setArtifact(defaultString(coordinates.getArtifactId()));
      //vuln.setExtension(defaultString(coordinates.getExtension()));
    }
    if (StringUtils.isNotEmpty(name)) {
      vuln.setArtifact(name);
    }

//  iqPrjVul.setMatchState(defaultString(component.getMatchState()));

    vuln.setSonatypeThreatLevel(defaultString(violation.getPolicyThreatLevel().toString()));
    vuln.setPriority(translateThreatLevelToPriority(vuln.getSonatypeThreatLevel()));

    // load vuln details from IQ
    try {
      VulnDetailResponse vulnDetail = iqClient.getVulnDetails(cve);

      if (vulnDetail == null) {
        vuln.setVulnerabilityAbstract("Vulnerability detail not available.");
      } else {
        vuln.setSource(defaultIfBlank(vulnDetail.getSource().getLongName(), "N/A"));

        // load component remediation from IQ
        RemediationResponse remediationResponse = iqClient.getCompRemediation(reportData.getApplicationId(),
            reportData.getStage(), component.getPackageUrl());

        String recommendedVersionMessage = describeRemediationResponse(vuln.getVersion(), remediationResponse);

        vuln.setVulnerabilityAbstract(buildAbstract(vulnDetail, recommendedVersionMessage));

        if (vulnDetail.getWeakness() != null) {
          List<CweId> cweIds = vulnDetail.getWeakness().getCweIds();
          if (!cweIds.isEmpty()) {
            CweId cweId = cweIds.get(0);
            vuln.setCwecwe(defaultIfBlank(cweId.getId(), "N/A"));
            vuln.setCweurl(defaultIfBlank(cweId.getUri(), "N/A"));
          }
        }

        List<SeverityScore> severityScores = vulnDetail.getSeverityScores();
        if (severityScores != null && !severityScores.isEmpty()) {
          vuln.setCvecvss2(defaultIfBlank(severityScores.get(0).getScore().toString(), "N/A"));
          if (severityScores.size() > 1) {
            vuln.setCvecvss3(defaultIfBlank(severityScores.get(1).getScore().toString(), "N/A"));
          }
        }

        MainSeverity mainSeverity = vulnDetail.getMainSeverity();
        if (mainSeverity != null) {
          vuln.setSonatypecvss3(defaultIfBlank(mainSeverity.getScore().toString(), "N/A"));
        }
      }
    } catch (Exception e) {
      logger.error("vulnDetails(" + cve + "): " + e.getMessage(), e);
    }

    return vuln;
  }

  private String buildAbstract(VulnDetailResponse vulnDetail, String recommendedVersionMessage) {
    return "<strong>Recommended Version(s): </strong>" + recommendedVersionMessage + "\r\n\r\n"
          + defaultString(vulnDetail.getDescription()) + "\r\n\r\n"
          + "<strong>Explanation: </strong>" + defaultString(vulnDetail.getExplanationMarkdown()) + "\r\n\r\n"
          + "<strong>Detection: </strong>" + defaultString(vulnDetail.getDetectionMarkdown()) + "\r\n\r\n"
          + "<strong>Recommendation: </strong>" + defaultString(vulnDetail.getRecommendationMarkdown()) + "\r\n\r\n"
          + "<strong>Threat Vectors: </strong>" + defaultString(vulnDetail.getMainSeverity().getVector());
  }

  private String describeRemediationResponse(String currentVersion, RemediationResponse remediationResponse) {
    List<VersionChange> versionChanges = remediationResponse.getRemediation().getVersionChanges();

    if (versionChanges != null && !versionChanges.isEmpty()) {
      String recommendedVersion = versionChanges.get(0).getData().getComponent().getComponentIdentifier()
          .getCoordinates().getVersion();
      if (recommendedVersion.equalsIgnoreCase(currentVersion)) {
        return "No recommended versions are available for the current component.";
      }
      return recommendedVersion;
    }

    return "No recommended versions are available for the current component.";
  }

  private Finding.Priority translateThreatLevelToPriority(String threatLevel) {
    int pPriority = Integer.parseInt(threatLevel);

    if (pPriority >= 8) {
      return Finding.Priority.Critical;
    }
    else if (pPriority > 4 && pPriority < 8) {
      return Finding.Priority.High;
    }
    else if (pPriority > 1 && pPriority < 4) {
      return Finding.Priority.Medium;
    }
    return Finding.Priority.Low;
  }

  /**
   * Check if new findings are different from previous saved content, then need to be uploaded to SSC.
   * 
   * @param project
   * @param stage
   * @param appProp
   * @param vulns
   * @return
   */
  private boolean checkSameFindings(String project, String stage, ApplicationProperties appProp,
      List<Finding> vulns) {
    // TODO: more accurate detection algorithm than just the count...
    return vulns.size() == countFindings(project, stage, appProp.getLoadLocation());
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

  private static String getJsonFilename(String appId, String stage) {
    return getJsonFilename(appId, stage, false);
  }

  private static String getJsonFilename(String appId, String stage, boolean backup) {
    return appId + '_' + stage + (backup ? ("_" + System.currentTimeMillis() + "_backup") : "") + ".json";
  }

  private File writeScanJsonToFile(Scan scan, String project, String stage, File loadLocation) {
    File file = new File(loadLocation, getJsonFilename(project, stage));
    logger.debug(SonatypeConstants.MSG_WRITE_DATA + file);

    ObjectMapper mapper = new ObjectMapper();
    try {
      mapper.writeValue(file, scan);
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

  public String killProcess() {
    String os = System.getProperty("os.name");
    logger.debug("OS is ::" + os);

    String processName = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
    String pId = processName.split("@")[0];
    logger.debug("pId is ::" + pId);
  
    try {
      String kill = os.startsWith("Windows") ? "taskkill /F /PID " : "kill -9 ";
      Runtime.getRuntime().exec(kill + pId);
      return "SUCCESS";
    }
    catch (IOException e) {
      logger.error(SonatypeConstants.ERR_KILL_PRC + e.getMessage(), e);
      return "FAILED";
    }
  }
}