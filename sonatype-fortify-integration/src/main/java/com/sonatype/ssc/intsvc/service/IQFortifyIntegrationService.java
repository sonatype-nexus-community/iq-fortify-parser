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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.stereotype.Service;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.media.multipart.file.FileDataBodyPart;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.media.multipart.MultiPart;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.*;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Component;
import com.sonatype.ssc.intsvc.model.PolicyViolation.PolicyViolationResponse;
import com.sonatype.ssc.intsvc.model.PolicyViolation.Violation;
import com.sonatype.ssc.intsvc.model.Remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.VulnDetailResponse;
import com.sonatype.ssc.intsvc.util.FortifyUtil;

@Service
public class IQFortifyIntegrationService
{
  private static final Logger logger = Logger.getRootLogger();

  private static final String ERROR_IQ_SERVER_API_CALL = "Error in call to IQ Server";

  public void startLoad(ApplicationProperties appProp, Map<String, String> passedMapped, boolean saveMapping) throws IOException {
      int totalCount = 0;
      int successCount = 0;
      if (passedMapped != null) {
          if (startLoadProcess(passedMapped, appProp)) {
              if (saveMapping) {
                //TODO: Save the passed mapping to the mapping file
              }
              logger.info(SonatypeConstants.MSG_DATA_CMP);
              logger.info("startLoad Completed: Passed project mapped used instead of mapping.json");
          }
      } else {
          List<Map<String, String>> applicationList = loadMapping(appProp.getMapFile());
          if (applicationList != null && !(applicationList.isEmpty())) {
              Iterator<Map<String, String>> iterator = applicationList.iterator();
              while (iterator.hasNext()) {
                  totalCount++;
                  Map<String, String> applicationMap = iterator.next();
                  if (startLoadProcess(applicationMap, appProp)) {
                      successCount++;
                  }
              }
          }
        logger.info(SonatypeConstants.MSG_DATA_CMP);
        logger.info(SonatypeConstants.MSG_TOT_CNT + totalCount);
        logger.info(SonatypeConstants.MSG_IQ_CNT + successCount + " projects");
    }
  }

  private boolean startLoadProcess(Map<String, String> applicationMap, ApplicationProperties appProp) throws IOException {
    boolean success = false;
    if (verifyMappingJSON(applicationMap)) {
      String iqDataFile = getIQVulnerabilityData(applicationMap.get(SonatypeConstants.IQ_PRJ),
          applicationMap.get(SonatypeConstants.IQ_STG), appProp);
      if (iqDataFile != null && iqDataFile.length() > 0) {
        logger.info(SonatypeConstants.MSG_SSC_DATA_WRT + iqDataFile);
        if (loadDataIntoSSC(applicationMap, appProp, iqDataFile)) {
          success = true;
        }
      }
    }
    return success;
  }

  private boolean verifyMappingJSON(Map<String, String> applicationMap) {
    boolean success = true;

    String iqProject = applicationMap.get(SonatypeConstants.IQ_PRJ);
    String iqPhase = applicationMap.get(SonatypeConstants.IQ_STG);
    String sscAppName = applicationMap.get(SonatypeConstants.SSC_APP);
    String sscAppVersion = applicationMap.get(SonatypeConstants.SSC_VER);

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

  @SuppressWarnings({"rawtypes", "unchecked"})
  public List<Map<String, String>> loadMapping(String fileName) {

    List<Map<String, String>> applicationList = new ArrayList<>();
    List<Map<String, String>> emptyList = new ArrayList<>();
    try {

      File file = new File(fileName);
      JSONParser parser = new JSONParser();
      JSONArray jArray = (JSONArray) parser.parse(new FileReader(file));
      if (!jArray.isEmpty()) {
        for (int i = 0; i < jArray.size(); i++) {
          Map<String, String> projectMap = new LinkedHashMap();
          projectMap.put(SonatypeConstants.IQ_PRJ,
              (String) ((JSONObject) jArray.get(i)).get(SonatypeConstants.IQ_PROJECT));
          projectMap.put(SonatypeConstants.IQ_STG,
              (String) ((JSONObject) jArray.get(i)).get(SonatypeConstants.IQ_PROJECT_STAGE));
          projectMap.put(SonatypeConstants.SSC_APP,
              (String) ((JSONObject) jArray.get(i)).get(SonatypeConstants.SSC_APPLICATION));
          projectMap.put(SonatypeConstants.SSC_VER,
              (String) ((JSONObject) jArray.get(i)).get(SonatypeConstants.SSC_APPLICATION_VERSION));
          applicationList.add(projectMap);
        }
      }
      return applicationList;
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

  public String getIQVulnerabilityData(String project, String version, ApplicationProperties appProp) {

    logger.debug(SonatypeConstants.MSG_READ_IQ_1 + project + SonatypeConstants.MSG_READ_IQ_2 + version);
    FortifyUtil fortifyutil = new FortifyUtil();
    String fileName = "";

    String iqGetInterAppIdApiURL = appProp.getIqServer() + SonatypeConstants.SSC_APP_ID_URL + project;
//    logger.debug("** iqGetInterAppIdApiURL: " + iqGetInterAppIdApiURL);
    String projectJSON = iqServerGetCall(iqGetInterAppIdApiURL, appProp.getIqServerUser(),
        appProp.getIqServerPassword());
    if (projectJSON.equalsIgnoreCase(ERROR_IQ_SERVER_API_CALL)) {
      return "";
    }

    String internalAppId = fortifyutil.getInternalApplicationId(projectJSON);
    logger.debug("Got internal application id from IQ: " + internalAppId);
    if (internalAppId != null && internalAppId.length() > 0) {
      String iqGetReportApiURL = appProp.getIqServer() + SonatypeConstants.SSC_REPORT_URL + internalAppId;

      IQProjectData iqProjectData = fortifyutil.getIQProjectData(
          iqServerGetCall(iqGetReportApiURL, appProp.getIqServerUser(), appProp.getIqServerPassword()), version,
          project);

      logger.debug("** project: " + project);

      if (iqProjectData.getProjectReportURL() != null && iqProjectData.getProjectReportURL().length() > 0) {

        if (isNewLoad(project, version, appProp, iqProjectData)) {

          //TODO: Get the policy based report here.
          String iqProjectReportID = iqProjectData.getProjectReportId();
          String iqGetPolicyReportApiURL = appProp.getIqServer() + SonatypeConstants.IQ_POLICY_REPORT_URL +
                  project + "/reports/" + iqProjectReportID + "/policy";
          logger.debug("** iqGetPolicyReportApiURL: " + iqGetPolicyReportApiURL);
          String iqPolicyReportResults = iqServerGetCall(iqGetPolicyReportApiURL, appProp.getIqServerUser(),
              appProp.getIqServerPassword());

          iqProjectData.setInternalAppId(internalAppId);
          logger.debug("** In getIQVulnerabilityData.  After setting internal app id: " + internalAppId);
          logger.debug("** In getIQVulnerabilityData.  iqPolicyReportResults: " + iqPolicyReportResults);

          //TODO: Parse the results of the policy violation report
          try {
            PolicyViolationResponse policyViolationResponse =
                    (new ObjectMapper()).readValue(iqPolicyReportResults,
                            PolicyViolationResponse.class);
            logger.debug("** Finding Current Count: " + countFindings(project, version, appProp));

            logger.debug("** before parsePolicyViolationResults");
            ArrayList<IQProjectVulnerability> finalProjectVulMap =  parsePolicyViolationResults(policyViolationResponse, appProp, iqProjectData);
            if (finalProjectVulMap == null) {
                return null;
            }

//          ArrayList<IQProjectVulnerability> finalProjectVulMap = readVulData(iqPolicyReport, appProp, iqProjectData);

            String projectIQReportURL = String.format(
                    "%s/%s/%s/%s",
                    SonatypeConstants.IQ_REPORT_URL,
                    iqProjectData.getProjectName(),
                    iqProjectData.getProjectReportId(),
                    appProp.getIqReportType()
            );

            iqProjectData.setTotalComponentCount(policyViolationResponse.getCounts().getTotalComponentCount());
            iqProjectData.setProjectIQReportURL(projectIQReportURL);

            logger.debug("** before createJSON: " + iqProjectData.toString());
            fileName = fortifyutil.createJSON(iqProjectData, finalProjectVulMap, appProp.getIqServer(),
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
              iqPrjVul.setCveurl(StringUtils.defaultString(getVulnDetailURL(CVE, appProp)));

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

              String vulDetailRest = getVulnDetailRestURL(CVE, appProp);
              logger.debug("vulDetailRest: " + vulDetailRest);
              String strResponseVulnDetails = iqServerGetCall(vulDetailRest, appProp.getIqServerUser(), appProp.getIqServerPassword());

              if (strResponseVulnDetails.equalsIgnoreCase("UNKNOWN")) {
                iqPrjVul.setVulnDetail(null);
                // Don't get the vuln details if we don't have
              } else {
                try {
                  VulnDetailResponse vulnDetailResponse =
                          (new ObjectMapper()).readValue(strResponseVulnDetails, VulnDetailResponse.class);
                  if (vulnDetailResponse != null) {
                    iqPrjVul.setVulnDetail(vulnDetailResponse);
                  }
                } catch (Exception e) {
                  logger.error("vulDetailRest: " + e.getMessage());
                }
              }

            try {

                iqPrjVul.setCompReportDetails(
                        iqServerPostCall(appProp.getIqServer() + "api/v2/components/details", appProp.getIqServerUser(), appProp.getIqServerPassword(), iqPrjVul.getPackageUrl()));

              String componentRemediationResults = iqServerPostCall(
                      getCompRemediationURL(appProp, iqProjectData), appProp.getIqServerUser(), appProp.getIqServerPassword(),
                      iqPrjVul.getPackageUrl());

              RemediationResponse remediationResponse =
                      (new ObjectMapper()).readValue(componentRemediationResults,
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


  private String getCompRemediationURL(ApplicationProperties appProp,
                                  IQProjectData iqProjectData)
  {
    // POST /api/v2/components/remediation/application/{applicationInternalId}?stageId={stageId}
    String compRemediationURL = "";
    compRemediationURL = appProp.getIqServer() + SonatypeConstants.SSC_COMP_REMEDIATION_URL
            + iqProjectData.getInternalAppId() + "?stageId="
            + iqProjectData.getProjectStage();
    //logger.debug("getCompRemediationURL: " + compRemediationURL);
    return compRemediationURL;
  }

  private String getVulnDetailURL(String CVE, ApplicationProperties appProp) {
    // Update to new vulnerability rest API
    // GET /api/v2/vulnerabilities/{vulnerabilityId}
    String vulnDetailURL = "";
    vulnDetailURL = appProp.getIqServer() + SonatypeConstants.IQ_VULNERABILITY_DETAIL_URL + CVE;
    logger.debug("** vulDetailURL: " + vulnDetailURL);
    return vulnDetailURL;
  }

  private String getVulnDetailRestURL(String CVE, ApplicationProperties appProp) {
    String vulnDetailRest = "";
    vulnDetailRest = appProp.getIqServer() + SonatypeConstants.IQ_VULNERABILITY_DETAIL_REST + CVE;
    logger.debug("** vulDetailURL: " + vulnDetailRest);
    return vulnDetailRest;
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

  private String iqServerGetCall(String apiUrl, String iqServerUsername, String iqServerPassword) {
    try {
      long start = System.currentTimeMillis();
      apiUrl = apiUrl.replaceAll(" ", "%20");
      String dataFromIQ = "";
      HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(iqServerUsername, iqServerPassword);
      Client client = ClientBuilder.newClient();
      client.register(feature);
      WebTarget target = client.target(apiUrl);
      Response response = target.request(MediaType.APPLICATION_JSON)
          .get();
      dataFromIQ = response.readEntity(String.class);
      long end = System.currentTimeMillis();
        logger.debug("*** iqServetGetCall ( " + apiUrl + ") Response time: " + (end - start) + " ms");

       if (response.getStatus() == 404) {
          return "UNKNOWN";
       }
      return dataFromIQ;
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_IQ_API + apiUrl);
      logger.debug("Error message::" + e.toString());
      return ERROR_IQ_SERVER_API_CALL;
    }
  }

  private String iqServerPostCall(String apiUrl, String iqServerUsername, String iqServerPassword, String packageUrl) {
    try {
        long start = System.currentTimeMillis();
      logger.debug("** In iqServerPostCall. apiUrl: " + apiUrl);
      IQRemediationRequest remediationRequest = new IQRemediationRequest();
      remediationRequest.setPackageUrl(packageUrl);
      logger.debug("** Setting packageUrl: " + packageUrl);

      apiUrl = apiUrl.replaceAll(" ", "%20");
      String dataFromIQ = "";
      HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(iqServerUsername, iqServerPassword);
      Client client = ClientBuilder.newClient();
      client.register(feature);
      WebTarget target = client.target(apiUrl);
//      logger.debug("** remediationRequest to json: " + remediationRequest.toJSONString());
      Response response = target.request(MediaType.APPLICATION_JSON).post(
              Entity.entity(remediationRequest.toJSONString(), MediaType.APPLICATION_JSON));
      dataFromIQ = response.readEntity(String.class);
        long end = System.currentTimeMillis();
        logger.debug("*** iqServetPostCall (" + apiUrl + ") Response time: " + (end - start) + " ms");
      return dataFromIQ;
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_IQ_API + apiUrl);
      logger.error("** Error message::" + e.getMessage());
      return ERROR_IQ_SERVER_API_CALL;
    }
  }

  private String sscServerGetCall(String apiUrl, String sscServerUsername, String sscServerPassword) {
    try {
      apiUrl = apiUrl.replaceAll(" ", "%20");
      String dataFromSSC = "";
      HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(sscServerUsername, sscServerPassword);
      Client client = ClientBuilder.newClient();
      client.register(feature);
      WebTarget target = client.target(apiUrl);
      Response response = target.request(MediaType.APPLICATION_JSON).get();
      dataFromSSC = response.readEntity(String.class);
      return dataFromSSC;
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_API + apiUrl);
      logger.debug("Error message::" + e.getMessage());
      return "ERROR_SSC_SERVER_API_CALL";
    }
  }

  private boolean loadDataIntoSSC(Map<String, String> applicationMap, ApplicationProperties appProp, String iqDataFile)
      throws IOException
  {
    boolean success = true;
    long sscAppId = getSSCApplicationId(applicationMap.get(SonatypeConstants.SSC_APP),
        applicationMap.get(SonatypeConstants.SSC_VER), appProp);
    if (sscAppId == 0) {
      sscAppId = getNewSSCApplicationId(applicationMap.get(SonatypeConstants.SSC_APP),
          applicationMap.get(SonatypeConstants.SSC_VER), appProp);
    }

    logger.debug("SSC Application id::" + sscAppId);
    if (sscAppId > 0) {
      try {
        if (!uploadVulnerabilityByProjectVersion(sscAppId, new File(iqDataFile), appProp)) {
          backupLoadFile(iqDataFile, applicationMap.get(SonatypeConstants.IQ_PRJ),
              applicationMap.get(SonatypeConstants.IQ_STG), appProp.getLoadLocation());
          success = false;
        }
      }
      catch (Exception e) {
        success = false;
        logger.error(SonatypeConstants.ERR_SSC_APP_UPLOAD + e.getMessage());
        backupLoadFile(iqDataFile, applicationMap.get(SonatypeConstants.IQ_PRJ),
            applicationMap.get(SonatypeConstants.IQ_STG), appProp.getLoadLocation());
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



  @SuppressWarnings("unchecked")
  public long getSSCApplicationId(String application, String version, ApplicationProperties appProp) {
    logger.info(SonatypeConstants.MSG_READ_SSC);

    long applicationId = 0;
    String apiURL = appProp.getSscServer() + SonatypeConstants.SSC_PROJECT_URL + application + "%22";
    logger.debug("SSC apiURL: " + apiURL);

    String strContent = sscServerGetCall(apiURL, appProp.getSscServerUser(), appProp.getSscServerPassword());
    if (strContent.equalsIgnoreCase("ERROR_SSC_SERVER_API_CALL")) {
      return -1;
    }
    else {
      try {

        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(strContent);
        JSONArray jData = (JSONArray) json.get("data");
        Iterator<JSONObject> iterator = jData.iterator();
        while (iterator.hasNext()) {
          JSONObject dataObject = iterator.next();
          String appVersion = (String) dataObject.get("name");
          if (appVersion.equalsIgnoreCase(version)) {
            applicationId = (long) dataObject.get("id");
            break;
          }
        }
        return applicationId;
      }
      catch (Exception e) {
        logger.error(SonatypeConstants.ERR_SSC_APP_ID + e.getMessage());
        return -1;
      }
    }
  }

  /**
   * This method creates new application version in the fortify server
   *
   * @param projectName String ,version String ,appProp IQProperties .
   * @return long.
   * @throws Exception, JsonProcessingException.
   */
  public long getNewSSCApplicationId(String projectName, String version, ApplicationProperties appProp) {

    logger.info(SonatypeConstants.MSG_SSC_APP_CRT);

    long applicationId = 0;
    long projectId = 0;
    try {

      String apiURL = appProp.getSscServer() + SonatypeConstants.PROJECT_VERSION_URL;
      SSCApplicationRequest applicationRequest = new SSCApplicationRequest();

      Client client = ClientBuilder.newClient();
      HttpAuthenticationFeature feature = HttpAuthenticationFeature
          .basic(appProp.getSscServerUser(), appProp.getSscServerPassword());
      client.register(feature);
      SSCProject project = new SSCProject();
      project.setDescription(SonatypeConstants.SSC_APPLICATION_DESCRIPTION);
      project.setIssueTemplateId(SonatypeConstants.SSC_APPLICATION_TEMPLATE_ID);
      project.setCreatedBy(SonatypeConstants.SSC_APPLICATION_CREATED_BY);
      project.setName(projectName);
      applicationRequest.setProject(project);
      applicationRequest.setActive(true);
      applicationRequest.setCommitted(true);
      applicationRequest.setName(version);
      applicationRequest.setDescription(SonatypeConstants.SSC_APPLICATION_DESCRIPTION);
      applicationRequest.setStatus(SonatypeConstants.SSC_APPLICATION_ACTIVE);
      applicationRequest.setIssueTemplateId(SonatypeConstants.SSC_APPLICATION_TEMPLATE_ID);

      String applicationRequestJson = applicationRequest.toJSONString();
      WebTarget webTarget = client.target(apiURL);
      Response applicationCreateResponse = webTarget.request()
          .post(Entity.entity(applicationRequestJson, MediaType.APPLICATION_JSON));

      if (applicationCreateResponse.getStatus() != 201) { // check whether application created or not-201 means
        // application created
        projectId = getProjectId(projectName, appProp); // if already application exists fetch the projectId
        if (projectId > 0) {
          project.setId(projectId);
          applicationRequest.setProject(project);
          applicationRequestJson = applicationRequest.toJSONString();
          applicationCreateResponse = webTarget.request()
              .post(Entity.entity(applicationRequestJson, MediaType.APPLICATION_JSON));
        }

      }
      logger.debug("Response Status........." + applicationCreateResponse.getStatus());

      if (applicationCreateResponse.getStatus() == 201) {
        String responseData = applicationCreateResponse.readEntity(String.class);
        logger.debug("Response Data ........." + responseData);
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(responseData);
        JSONObject jData = (JSONObject) json.get(SonatypeConstants.DATA);
        applicationId = (long) jData.get(SonatypeConstants.ID);
        updateApplication(applicationId, client, appProp);
      }
      else {
        logger.error(SonatypeConstants.ERR_APP_DEACT);
        applicationId = -1;
      }

    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_CRT_APP + e.getMessage());

    }
    logger.debug("End of Method getNewSSCApplicationId..");
    return applicationId;
  }

  private void updateApplication(long applicationId, Client client, ApplicationProperties appProp) {
    try {
      if (updateAttributes(applicationId, client, appProp)) {
        commitApplication(applicationId, client, appProp);

      }
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_JSON + e.getMessage());
    }
  }

  /**
   * This method creates mandatory attributes of the new application created in
   * the fortify server
   *
   * @param applicationId long, Client client, appProp IQProperties .
   * @return boolean status
   */
  public boolean updateAttributes(long applicationId, Client client, ApplicationProperties appProp) {

    logger.debug("Start of Method updateAttributes.......");

    try {


      StringBuilder apiURL = new StringBuilder(appProp.getSscServer())
          .append(SonatypeConstants.PROJECT_VERSION_URL).append(SonatypeConstants.SLASH).append(applicationId)
          .append(SonatypeConstants.ATTRIBUTES);

      WebTarget resource = client.target(apiURL.toString());
      Response response = resource.request(MediaType.APPLICATION_JSON)
          .put(Entity.entity(SonatypeConstants.UPDATE_ATTRIBUTE_STRING, MediaType.APPLICATION_JSON));
      logger.debug("updateAttributesResponse:: " + response);

    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_EXCP + e.getMessage());

    }

    logger.debug("End of Method updateAttributes........");
    return true;
  }

  /**
   * This method commits new application created in the fortify server
   *
   * @param applicationId long ,Client client ,appProp IQProperties .
   * @return boolean
   */
  public boolean commitApplication(long applicationId, Client client, ApplicationProperties appProp) {
    logger.debug("Start of Method commitApplication..");

    StringBuilder apiURL = new StringBuilder(appProp.getSscServer()).append(SonatypeConstants.PROJECT_VERSION_URL)
        .append(SonatypeConstants.SLASH).append(applicationId);

    WebTarget target = client.target(apiURL.toString());
    Response response = target.request(MediaType.APPLICATION_JSON)
        .put(Entity.entity(SonatypeConstants.COMMIT_JSON, MediaType.APPLICATION_JSON));

    if (response.getStatus() != 200) {
      return false;
    }
    logger.debug("End of Method commitApplication..");
    return true;

  }

  @SuppressWarnings("unchecked")
  private long getProjectId(String applicationName, ApplicationProperties appProp) {
    logger.debug("Start of Method getProjectId........");

    long projectId = 0;

    String apiURL = appProp.getSscServer() + SonatypeConstants.PROJECT_URL;

    Client client = ClientBuilder.newClient();
    HttpAuthenticationFeature feature = HttpAuthenticationFeature
        .basic(appProp.getSscServerUser(), appProp.getSscServerPassword());
    client.register(feature);
    WebTarget resource = client.target(apiURL);
    Response response = resource.request(MediaType.APPLICATION_JSON).get();
    String dataFromSSC = response.readEntity(String.class);

    try {
      JSONParser parser = new JSONParser();
      JSONObject json = (JSONObject) parser.parse(dataFromSSC);
      JSONArray jData = (JSONArray) json.get(SonatypeConstants.DATA);
      Iterator<JSONObject> iterator = jData.iterator();
      while (iterator.hasNext()) {
        JSONObject dataObject = iterator.next();
        String appName = (String) dataObject.get(SonatypeConstants.NAME);
        if (applicationName.equalsIgnoreCase(appName)) {
          projectId = (long) dataObject.get(SonatypeConstants.ID);
          break;
        }
      }
      logger.debug("projectId:::" + projectId);
      logger.debug("End of Method getProjectId......");

      return projectId;
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_PRJ_EXP + e.getMessage());

      return projectId;
    }
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

  /**
   * This method fetches the file token from fortify server
   *
   * @param appProp IQProperties .
   * @return String.
   */
  public String getFileToken(ApplicationProperties appProp) throws ParseException {

    String apiURL = appProp.getSscServer() + SonatypeConstants.FILE_TOKEN_URL;

    HttpAuthenticationFeature feature = HttpAuthenticationFeature
        .basic(appProp.getSscServerUser(), appProp.getSscServerPassword());
    Client client = ClientBuilder.newClient();
    client.register(feature);

    WebTarget target = client.target(apiURL);

    Response applicationCreateResponse = target.request()
        .post(Entity.entity(SonatypeConstants.FILE_TOKEN_JSON, MediaType.APPLICATION_JSON));

    String responseData = applicationCreateResponse.readEntity(String.class);

    JSONParser parser = new JSONParser();
    JSONObject json = (JSONObject) parser.parse(responseData);
    JSONObject jData = (JSONObject) json.get(SonatypeConstants.DATA);
    return (String) jData.get(SonatypeConstants.TOKEN);

  }

  @SuppressWarnings("resource")
  public boolean uploadVulnerabilityByProjectVersion(final long entityIdVal, final File file, ApplicationProperties appProp)
      throws IOException
  {

    Client client = ClientBuilder.newBuilder().register(MultiPartFeature.class).build();

    try {
      logger.debug("Uploading data in SSC");

      HttpAuthenticationFeature feature = HttpAuthenticationFeature
          .basic(appProp.getSscServerUser(), appProp.getSscServerPassword());
      client.register(feature);

      String apiURL = appProp.getSscServer() + SonatypeConstants.FILE_UPLOAD_URL;
      WebTarget resource = client.target(apiURL + getFileToken(appProp));

      FileDataBodyPart fileDataBodyPart = new FileDataBodyPart(SonatypeConstants.FILE, file,
          MediaType.APPLICATION_OCTET_STREAM_TYPE);
      try (MultiPart multiPart = new FormDataMultiPart()
          .field(SonatypeConstants.ENTITY_ID, String.valueOf(entityIdVal), MediaType.TEXT_PLAIN_TYPE)
          .field(SonatypeConstants.ENTITY_TYPE, SonatypeConstants.SONATYPE, MediaType.TEXT_PLAIN_TYPE)
          .bodyPart(fileDataBodyPart)) {

        multiPart.setMediaType(MediaType.MULTIPART_FORM_DATA_TYPE);
        Response response = resource.request(MediaType.MULTIPART_FORM_DATA)
            .post(Entity.entity(multiPart, multiPart.getMediaType()));

        logger.debug("response::" + response.getStatus());
        if (response.getStatus() == 200) {
          return true;
        }
        else {
          logger.error(SonatypeConstants.ERR_SSC_UPLOAD);
          return false;
        }

      }
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_UPLOAD + e.getMessage());
      return false;

    }
    finally {
      client.close();
      deletetFileToken(appProp);
    }

  }

  public void deleteLoadFile(String fileName) throws IOException {
    Path filePath = Paths.get(fileName);
    logger.info(SonatypeConstants.MSG_DLT_FILE + fileName);
    Files.delete(filePath);
  }

  /**
   * This method deletes  the file token from fortify server
   *
   * @param  appProp IQProperties .
   * @return String.
   * @throws Exception, JsonProcessingException.
   */
  private boolean deletetFileToken(ApplicationProperties appProp) {

    try {
      String apiURL = appProp.getSscServer() + SonatypeConstants.FILE_TOKEN_URL;

      HttpAuthenticationFeature feature = HttpAuthenticationFeature
          .basic(appProp.getSscServerUser(), appProp.getSscServerPassword());
      Client client = ClientBuilder.newClient();
      client.register(feature);
      WebTarget target = client.target(apiURL);

      Response applicationCreateResponse = target.request(MediaType.APPLICATION_JSON).delete();
      logger.debug("applicationCreateResponse:::" + applicationCreateResponse);
      return true;
    }
    catch (Exception e) {
      logger.error("Exception occured while deleting the  file token::" + e.getMessage());
      return false;

    }

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
