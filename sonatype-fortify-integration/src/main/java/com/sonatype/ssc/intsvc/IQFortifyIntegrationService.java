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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.apache.commons.lang3.StringUtils.defaultString;
import static org.apache.commons.lang3.StringUtils.defaultIfBlank;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonatype.ssc.intsvc.iq.IQClient;
import com.sonatype.ssc.intsvc.iq.IQReportData;
import com.sonatype.ssc.intsvc.iq.policyViolation.Component;
import com.sonatype.ssc.intsvc.iq.policyViolation.ComponentIdentifier;
import com.sonatype.ssc.intsvc.iq.policyViolation.Coordinates;
import com.sonatype.ssc.intsvc.iq.policyViolation.PolicyViolationResponse;
import com.sonatype.ssc.intsvc.iq.policyViolation.Violation;
import com.sonatype.ssc.intsvc.iq.remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.iq.remediation.VersionChange;
import com.sonatype.ssc.intsvc.iq.scanhistory.Report;
import com.sonatype.ssc.intsvc.iq.vulnerabilityDetail.CweId;
import com.sonatype.ssc.intsvc.iq.vulnerabilityDetail.MainSeverity;
import com.sonatype.ssc.intsvc.iq.vulnerabilityDetail.SeverityScore;
import com.sonatype.ssc.intsvc.iq.vulnerabilityDetail.VulnDetailResponse;
import com.sonatype.ssc.model.Scan;
import com.sonatype.ssc.model.Finding;
import com.sonatype.ssc.intsvc.ssc.SSCClient;

/**
 * Core integration service, doing for each {@link IQSSCMapping IQ-SSC mapping} required ETL job:<ul>
 * <li>extract report from IQ using {@link IQClient},</li>
 * <li>transform IQ-oriented data ({@link IQReportData}, {@link ScanHistory}, {@link PolicyViolationResponse}, {@link RemediationResponse}, ...)
 * to Fortify-oriented {@link Scan} and {@link Finding}s,</li>
 * <li>load these {@link Finding findings} to SSC using {@link SSCClient}.</li></ul>
 */
@Service
public class IQFortifyIntegrationService
{
  private static final Logger logger = Logger.getRootLogger();

  public void startLoad(ApplicationProperties appProp) throws IOException {
    int totalCount = 0;
    int successCount = 0;
    long begin = System.currentTimeMillis();
    List<IQSSCMapping> mappings = loadMapping(appProp);
    if (mappings != null) {
      for (IQSSCMapping applicationMapping : mappings) {
        totalCount++;
        if (executeETLProcess(applicationMapping, appProp)) {
          successCount++;
        }
      }
    }
    long end = System.currentTimeMillis();
    logger.info("Data extraction and upload complete: " + totalCount + " IQ extractions for " + successCount + " SSC uploads");
    ApplicationProperties.RunStatistics stat = appProp.runStatistics;
    logger.info("Run statistics for " + totalCount + " mappings (" + (end - begin)/1000 + "s)" + ": "
        + "IQ reports checked: " + stat.iqReports.describe() + ", " + stat.iqReports.failed + " missing, " + stat.iqReportsSameScanDate + " without new scan; "
        + "violations listing for reports: " + stat.iqReportPolicyViolations.describe() + ", same findings: " + stat.iqReportsSameFindings + " reports with " + stat.iqReportsSameFindingsViolations + " violations; "
        + "violation details research: " + stat.iqViolationsDetails.describe() + ", " + stat.iqPreviousFinding + " existing, " + stat.iqNewFinding + " new; "
        + "SSC scan loads: " + stat.sscLoad.describe());
  }

  public void startLoad(ApplicationProperties appProp, IQSSCMapping iqSscMapping, boolean saveMapping)
      throws IOException {
    if (executeETLProcess(iqSscMapping, appProp)) {
      if (saveMapping) {
        saveMapping(appProp, iqSscMapping);
      }
    }
    logger.info("Data upload complete.");
  }

  private synchronized boolean executeETLProcess(IQSSCMapping iqSscMapping, ApplicationProperties appProp) throws IOException {
    if (!iqSscMapping.verifyMapping(logger)) {
      return false;
    }

    // get data from IQ then save to JSON
    File iqDataFile;
    try {
      iqDataFile = extractTransformIQScanData(iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp);
    } catch (Error e) {
      logger.error("Unexpected extraction error from " + iqSscMapping.getIqProject() + " with phase "
          + iqSscMapping.getIqProjectStage(), e);
      //throw e;
      iqDataFile = null;
    }

    if (iqDataFile == null) {
      return false;
    }

    logger.info("Data written into JSON file: " + iqDataFile);

    // save data to SSC
    ApplicationProperties.Counter counter = appProp.runStatistics.sscLoad;
    try {
      counter.begin();
      return loadDataIntoSSC(iqSscMapping, appProp, iqDataFile);
    } catch (Error e) {
      logger.error("Unexpected load error to " + iqSscMapping.getSscApplication() + " with version "
          + iqSscMapping.getSscApplicationVersion(), e);
      counter.fail();
      //throw e;
    } finally {
      counter.end();
    }
    return false;
  }

  /**
   * Extract IQ scan data on an IQ application in defined stage, transform it to findings, then save
   * findings to a JSON file if there are new results (compared against last save).
   *
   * @param project the IQ public application id
   * @param stage   the IQ stage to look at
   * @param appProp the app configuration to access IQ
   * @return the JSON file containing extracted scan data from IQ (or null if any
   *         issue or new extraction got the same result that previous run)
   * @see #saveScanDataAsJSON(SonatypeScan, List, String, File)
   */
  private File extractTransformIQScanData(String project, String stage, ApplicationProperties appProp) {

    logger.debug(String.format("Getting data from IQ Server for project: %s with phase: %s", project, stage));
    IQClient iqClient = appProp.getIqClient();

    String internalAppId;
    IQReportData reportData;
    ApplicationProperties.Counter counter = appProp.runStatistics.iqReports;
    try { // base report data
      counter.begin();
      internalAppId = iqClient.getInternalApplicationId(project);

      if (StringUtils.isBlank(internalAppId)) {
        counter.fail();
        logger.info(String.format("No project: %s with phase: %s available in IQ server", project, stage));
        return null;
      }

      // get base Sonatype scan data from IQ report for application and stage
      logger.info(String.format("Getting IQ report data for: %s with phase: %s", project, stage));
      reportData = iqClient.getReportData(project, internalAppId, stage);

      if (reportData == null) {
        counter.fail();
        logger.info(String.format("No report available for: %s with phase: %s in IQ server", project, stage));
        return null;
      }
    } finally {
      counter.end();
    }

    Scan scan = new Scan();
    scan.setEngineVersion("1.0");
    scan.setScanDate(reportData.getEvaluationDate());
    scan.setBuildServer(project);

    if (scan.getScanDate().equals(getLastScanDate(project, stage, appProp.getLoadLocation()))) {
      // current report evaluation date is the same as last save: no new data
      logger.info(String.format("Evaluation date of report and scan date of last load file is same, hence for %s with phase: %s, no new data is available for import", project, stage));
      appProp.runStatistics.iqReportsSameScanDate++;
      return null;
    }

    try {
      // extract policy violations from IQ report
      counter = appProp.runStatistics.iqReportPolicyViolations;
      PolicyViolationResponse policyViolationResponse;
      try {
        counter.begin();
        policyViolationResponse = iqClient.getPolicyViolationsByReport(project, reportData.getReportId());
      } finally {
        counter.end();
      }

      // fill build server field with "<type>,<initiator>", with type=isNew/isReevaluation/isForMonitoring
      // it will be displayed in SSC "ARTIFACTS" view as "Hostname"
      String buildServer = "unknown";
      // require data from scan history (available since IQ release 94)
      try {
        counter = appProp.runStatistics.iqScanReportFromHistory;
        Report report = iqClient.getScanReportFromHistory(internalAppId, stage);
        if (report != null) {
          if (report.getIsForMonitoring()) {
            buildServer = "isForMonitoring";
          }
          else {
            buildServer = report.getIsReevaluation() ? "isReevaluation" : "isNew";
          }
          String initiator = policyViolationResponse.getInitiator();
          if (StringUtils.isNotEmpty(initiator)) {
            buildServer += "," + initiator;
          }
        }
      } catch (Exception e) {
        // optional data, don't fail: probably just an older IQ release
        buildServer = "require IQ 94";
        counter.fail();
        logger.warn("getScanReportFromHistory(" + project + ", " + stage + "): please upgrade Nexus IQ to release 94 minimum", e);
      } finally {
        counter.end();
      }
      scan.setBuildServer(buildServer);

      scan.setNumberOfFiles(policyViolationResponse.getCounts().getTotalComponentCount());

      // select violations to send to SSC
      List<Pair<Violation, Component>> violations = selectPolicyViolationResults(policyViolationResponse, appProp, reportData);

      // check if new violations were found vs last save
      Map<String, Finding> prevFindings = checkSameFindings(project, stage, appProp, violations);
      if (prevFindings == null) {
        logger.info(String.format("Findings for: %s with phase: %s are the same as previous scan, no new data is available for import", project, stage));
        appProp.runStatistics.iqReportsSameFindings++;
        appProp.runStatistics.iqReportsSameFindingsViolations+= violations.size();
        return null;
      }

      // translate these violations to findings for SSC
      counter = appProp.runStatistics.iqViolationsDetails;
      counter.begin();
      List<Finding> vulns = new ArrayList<>(violations.size());
      for ( Pair<Violation, Component> violation: violations) {
        if (prevFindings.containsKey(violation.getLeft().getPolicyViolationId())) {
          appProp.runStatistics.iqPreviousFinding++;
          // reuse previous finding as saved on disk on previous run?
        } else {
          appProp.runStatistics.iqNewFinding++;
        }
        // create 1 vuln/1 finding per violation that is not ignored
        Finding vuln = fromSecurityViolationToVuln(violation.getRight(), violation.getLeft(), appProp, reportData);
        if (vuln != null) {
          vuln.setReportUrl(reportData.getReportUrl());
          vulns.add(vuln);
        }
      }
      counter.end(vulns.size());
      scan.setFindings(vulns);

      return writeScanJsonToFile(scan, project, stage, appProp.getLoadLocation());

    } catch (Exception e) {
      logger.error("getScanData(" + project + ", " + stage + "):" + e.getMessage(), e);
    }
    return null;
  }

  /**
   * Select IQ Policy violation results interesting to send to SSC.
   * 
   * @param policyViolationResponse policy violations read from IQ
   * @param appProp integration service configuration
   * @param reportData current report data
   * @return the list of violations and associated component to be sent to SSC
   */
  private List<Pair<Violation, Component>> selectPolicyViolationResults(
      PolicyViolationResponse policyViolationResponse, ApplicationProperties appProp, IQReportData reportData) {

    List<Pair<Violation, Component>> violations = new ArrayList<>();

    int componentsWithViolations = 0;
    int allViolations = 0;
    int waived = 0;
    int grandfathered = 0;
    Map<String, AtomicLong> threatCategories = new TreeMap<>();

    for (Component component : policyViolationResponse.getComponents()) {
      if (component.getViolations() == null || component.getViolations().size() == 0) {
        // no violation: skip component
        continue;
      }

      componentsWithViolations++;
      allViolations += component.getViolations().size();

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

        violations.add(Pair.of(violation, component));
      }
    }

    logger.debug("summary: on " + policyViolationResponse.getComponents().size() + " components, "
        + componentsWithViolations + " had policy violations for " + allViolations + " violations: " + waived + " waived, "
        + grandfathered + " grandfathered, " + threatCategories);
    return violations;
  }

  private static final Pattern PATTERN = Pattern.compile("Found security vulnerability (.*) with");

  private Finding fromSecurityViolationToVuln(Component component, Violation violation, ApplicationProperties appProp,
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
    IQClient iqClient = appProp.getIqClient();

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
    vuln.setPriority(translateThreatLevelToPriority(appProp, Integer.parseInt(vuln.getSonatypeThreatLevel())));

    // load vuln details from IQ
    try {
      VulnDetailResponse vulnDetail = iqClient.getVulnDetails(cve);

      if (vulnDetail == null) {
        vuln.setVulnerabilityAbstract("Vulnerability detail not available.");
      } else {
        vuln.setSource(defaultIfBlank(vulnDetail.getSource().getLongName(), "N/A"));

        // load component remediation from IQ to define vulnerability abstract
        try {
          RemediationResponse remediationResponse = iqClient.getCompRemediation(reportData.getApplicationId(),
              reportData.getStage(), component.getPackageUrl());

          String recommendedVersionMessage = describeRemediationResponse(vuln.getVersion(), remediationResponse);

          vuln.setVulnerabilityAbstract(buildAbstract(vulnDetail, recommendedVersionMessage));
        } catch (Exception e) {
          logger.warn("compRemediation(" + component.getPackageUrl() + ")", e);
          // fallback to basic vulnerability description without remediation
          vuln.setVulnerabilityAbstract(defaultString(vulnDetail.getDescription()));
        }

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
      logger.error("vulnDetails(" + cve + ")", e);
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

  /**
   * Translate Nexus IQ threat level to Fortify SSC priority.
   *
   * @param threatLevel the policy threat level
   * @return translated priority
   * @see https://help.sonatype.com/iqserver/managing/policy-management/understanding-the-parts-of-a-policy#UnderstandingthePartsofaPolicy-ThreatLevel
   */
  private Finding.Priority translateThreatLevelToPriority(ApplicationProperties appProp, int threatLevel) {
    if (threatLevel >= appProp.getPriorityCritical()) {
      return Finding.Priority.Critical;
    }
    else if (threatLevel >= appProp.getPriorityHigh()) {
      return Finding.Priority.High;
    }
    else if (threatLevel >= appProp.getPriorityMedium()) {
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
   * @param violations
   * @return {@code null} if same findings, a map of findings keyed on violation id
   */
  private Map<String, Finding> checkSameFindings(String project, String stage, ApplicationProperties appProp,
      List<Pair<Violation, Component>> violations) {
    Scan prev = loadPrevious(project, stage, appProp.getLoadLocation());

    // extract current uniqueIds
    Set<String> ids = new HashSet<>();
    for(Pair<Violation, Component> p: violations) {
      ids.add(p.getLeft().getPolicyViolationId());
    }
    // extract previous uniqueIds
    Map<String, Finding> prevFindings = new HashMap<>();
    if (prev != null) {
      for (Finding f : prev.getFindings()) {
        prevFindings.put(f.getUniqueId(), f);
      }
    }

    // consider same findings if same uniqueIds, ignoring if content detail has changed
    if (ids.equals(prevFindings.keySet())) {
      return null;
    }
    return prevFindings;
  }

  private boolean loadDataIntoSSC(IQSSCMapping iqSscMapping, ApplicationProperties appProp, File scanDataFile)
      throws IOException
  {
    SSCClient sscClient = appProp.getSscClient();
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
        logger.error("Error in startScanLoad while loading data in fortify::" + e.getMessage(), e);
        backupLoadFile(scanDataFile, iqSscMapping.getIqProject(), iqSscMapping.getIqProjectStage(), appProp.getLoadLocation());
      }
    }
    else if (sscAppId == -1) {
      deleteLoadFile(scanDataFile);
      success = false;
    }
    else {
      logger.error("Not able to found and create application in SSC server.");
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
    logger.debug("Writing data into JSON file ::" + file);

    ObjectMapper mapper = new ObjectMapper();
    try {
      mapper.writeValue(file, scan);
      return file;
    } catch (IOException e) {
      logger.error("Error while createJSON :: " + e.getMessage());
    }
    return null;
  }

  private Scan loadPrevious(String project, String stage, File loadLocation) {
    File prevFile = new File(loadLocation, getJsonFilename(project, stage));
    if (prevFile.exists()) {
      try {
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        ;
        return mapper.readValue(prevFile, Scan.class);
      }
      catch (Exception e) {
        logger.error("Could not read save file: " + prevFile + ": " + e.getMessage(), e);
      }
    }
    return null;
  }

  private void deleteLoadFile(File file) throws IOException {
    logger.info("Deleted the load file: " + file);
    file.delete();
  }

  private void backupLoadFile(File loadFile, String iqProject, String iqPhase, File loadLocation) {
    try {
      if (loadFile.renameTo(new File(loadLocation, getJsonFilename(iqProject, iqPhase, true)))) {
        logger.info("Created backup of load file: " + loadFile.getName());
      }
    } catch (Exception e) {
      logger.error("Exception occured while renaming the load file: " + e.getMessage());
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
    Scan scan = loadPrevious(project, stage, loadLocation);
    if (scan != null) {
      return scan.getScanDate();
    }
    return null;
  }

  public List<IQSSCMapping> loadMapping(ApplicationProperties appProp) {
    List<IQSSCMapping> emptyList = new ArrayList<>();
    try {
      return appProp.loadMapping();
    }
    catch (FileNotFoundException e) {
      logger.fatal("Mapping JSON file not found ::" + e.getMessage());
      return emptyList;
    }
    catch (IOException e) {
      logger.fatal("IOException exception in reading mapping json ::" + e.getMessage());
      return emptyList;
    }
    catch (Exception e) {
      logger.error("Exception occured while reading JSON file::" + e.getMessage());
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
      logger.error("Error in killing the process::" + e.getMessage(), e);
      return "FAILED";
    }
  }
}