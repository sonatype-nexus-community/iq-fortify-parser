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
package com.sonatype.ssc.intsvc.util;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.IQProjectData;
import com.sonatype.ssc.intsvc.model.IQProjectVulnerability;
import com.sonatype.ssc.intsvc.model.IQRemediationRequest;
import com.sonatype.ssc.intsvc.model.Remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.VulnDetailResponse;

/**
 * utility to read IQ REST APIs results
 */
public class IQClient
{
  private static final Logger logger = Logger.getRootLogger();

  private static final String ERROR_IQ_SERVER_API_CALL = "Error in call to IQ Server";

  private static final String CONT_SRC = "source";

  private static final String CONT_DESC = "description";

  private static final String CONT_CWECWE = "cwecwe";

  private static final String CONT_CVSS2 = "cvecvss2";

  private static final String CONT_CVSS3 = "cvecvss3";

  private static final String CONT_CWEURL = "cweurl";

  private static final String CONT_PACK_URL = "packageUrl";

  private static final String CONT_ST_CVSS3 = "sonatypecvss3";

  private final ApplicationProperties appProp;

  public IQClient(ApplicationProperties appProp) {
    this.appProp = appProp;
  }

  public String getInternalApplicationId(String publicId) {
    String iqGetInterAppIdApiURL = appProp.getIqServer() + SonatypeConstants.SSC_APP_ID_URL + publicId;
    // logger.debug("** iqGetInterAppIdApiURL: " + iqGetInterAppIdApiURL);
    String jsonStr = iqServerGetCall(iqGetInterAppIdApiURL);
    if (jsonStr.equalsIgnoreCase(ERROR_IQ_SERVER_API_CALL)) {
      return "";
    }

    String internalAppId = "";
    if (jsonStr != null && jsonStr.length() > 0) {
      try {
        JSONObject json = (JSONObject) new JSONParser().parse(jsonStr);
        JSONArray applications = (JSONArray) json.get("applications");
        @SuppressWarnings("unchecked")
        Iterator<JSONObject> iterator = applications.iterator();
        while (iterator.hasNext()) {
          JSONObject dataObject = iterator.next();
          internalAppId = (String) dataObject.get("id");
        }
      } catch (Exception e) {
        logger.error(SonatypeConstants.ERR_GET_INT_APP_ID + e.getMessage());
      }
    }
    return internalAppId;
  }

  public String getPolicyReport(String publicId, String reportId) {
    String iqGetPolicyReportApiURL = appProp.getIqServer() + SonatypeConstants.IQ_POLICY_REPORT_URL + publicId
        + "/reports/" + reportId + "/policy";
    logger.debug("** iqGetPolicyReportApiURL: " + iqGetPolicyReportApiURL);
    return iqServerGetCall(iqGetPolicyReportApiURL);
  }

  @SuppressWarnings("unchecked")
  public String saveIqDataAsJSON(IQProjectData iqPrjData,
                           List<IQProjectVulnerability> iqPrjVul,
                           String iqServerURL,
                           String loadLocation)
  {
    logger.debug(SonatypeConstants.MSG_WRITE_DATA);
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

  private String writeJsonToFile(final IQProjectData iqPrjData, final String loadLocation, final JSONObject json) {
    String fileName;
    fileName = loadLocation + iqPrjData.getProjectName() + "_" + iqPrjData.getProjectStage() + ".json";

    try (FileWriter file = new FileWriter(fileName)) {

      file.write(json.toJSONString());
      file.flush();
      return fileName;
    }
    catch (IOException e) {
      logger.error(SonatypeConstants.ERR_WRITE_LOAD + e.getMessage());
      return "";
    }
  }

  public String buildDescription(VulnDetailResponse vulnDetail, IQProjectVulnerability iqProjectVul) {
    String desc = "";
    logger.debug("** In createJSON in buildDescription");

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

  public String parseRemediationResponse(RemediationResponse response, IQProjectVulnerability iqProjectVul) {
    if (response.getRemediation().getVersionChanges() != null && !response.getRemediation().getVersionChanges().isEmpty()) {
      logger.debug(("*** getVersionChanges: ") + response.getRemediation().getVersionChanges().toString());
      logger.debug("*** Attempting to get Recommended Version: ");
      String recommendedVersion = response.getRemediation().getVersionChanges().get(0).getData().getComponent().getComponentIdentifier().getCoordinates().getVersion();
      logger.debug("*** Recommended Version: " + recommendedVersion);
      logger.debug("*** Actual Version: " + iqProjectVul.getVersion());
      if (recommendedVersion.equalsIgnoreCase(iqProjectVul.getVersion())) {
        return "No recommended versions are available for the current component.";
      }
      return recommendedVersion;
    }

    return "No recommended versions are available for the current component.";


  }


  public String getPriority(String threatLevel) {
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

  public IQProjectData getIQProjectData(String internalAppId, String prjStage, String prjName)
  {
    logger.info(SonatypeConstants.MSG_GET_IQ_DATA);
    String iqGetReportApiURL = appProp.getIqServer() + SonatypeConstants.SSC_REPORT_URL + internalAppId;
    String jsonStr = iqServerGetCall(iqGetReportApiURL);

    IQProjectData iqProjectData = new IQProjectData();
    try {
      JSONParser parser = new JSONParser();
      JSONArray json = (JSONArray) parser.parse(jsonStr);
      @SuppressWarnings("unchecked")
      Iterator<JSONObject> iterator = json.iterator();
      while (iterator.hasNext()) {
        JSONObject dataObject = iterator.next();
        String projectStage = (String) dataObject.get("stage");
        if (projectStage.equalsIgnoreCase(prjStage)) {
          iqProjectData.setProjectReportURL((String) dataObject.get("reportDataUrl"));
          iqProjectData.setProjectPublicId((String) dataObject.get("publicId"));
          iqProjectData.setEvaluationDate((String) dataObject.get("evaluationDate"));
          iqProjectData.setProjectReportId(getReportId((String) dataObject.get("reportHtmlUrl")));
          iqProjectData.setProjectStage(prjStage);
          iqProjectData.setProjectName(prjName);
          break;
        }
      }
    }
    catch (Exception e) {
      logger.error("Error in getting internal application id from IQ: " + e.getMessage());
    }
    iqProjectData.setInternalAppId(internalAppId);
    return iqProjectData;
  }

  private String getReportId(String reportUrl) {
    return reportUrl.substring(reportUrl.indexOf("/report/") + 8, reportUrl.length());
  }

  public String getVulnDetailURL(String CVE, ApplicationProperties appProp) {
    // Update to new vulnerability rest API
    // GET /api/v2/vulnerabilities/{vulnerabilityId}
    String vulnDetailURL = appProp.getIqServer() + SonatypeConstants.IQ_VULNERABILITY_DETAIL_URL + CVE;
    logger.debug("** vulDetailURL: " + vulnDetailURL);
    return vulnDetailURL;
  }

  public String getVulnDetail(String CVE, ApplicationProperties appProp) {
    String vulnDetailRest = appProp.getIqServer() + SonatypeConstants.IQ_VULNERABILITY_DETAIL_REST + CVE;
    logger.debug("** vulDetailURL: " + vulnDetailRest);
    return iqServerGetCall(vulnDetailRest);
  }

  public String getComponentDetails(String packageUrl) {
    return iqServerPostCall(appProp.getIqServer() + "api/v2/components/details", packageUrl);
  }

  public String getCompRemediation(IQProjectData iqProjectData, String packageUrl) {
    // POST /api/v2/components/remediation/application/{applicationInternalId}?stageId={stageId}
    String compRemediationURL = appProp.getIqServer() + SonatypeConstants.SSC_COMP_REMEDIATION_URL
        + iqProjectData.getInternalAppId() + "?stageId=" + iqProjectData.getProjectStage();
    //logger.debug("getCompRemediationURL: " + compRemediationURL);
    return iqServerPostCall(compRemediationURL, packageUrl);
  }

  private Builder prepareIqCall(String apiUrl) {
    apiUrl = apiUrl.replaceAll(" ", "%20");
    HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(appProp.getIqServerUser(),
        appProp.getIqServerPassword());
    Client client = ClientBuilder.newClient();
    client.register(feature);
    WebTarget target = client.target(apiUrl);
    return target.request(MediaType.APPLICATION_JSON);
  }

  private String iqServerGetCall(String apiUrl) {
    try {
      long start = System.currentTimeMillis();
      Response response = prepareIqCall(apiUrl).get();
      String dataFromIQ = response.readEntity(String.class);
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

  private String iqServerPostCall(String apiUrl, String packageUrl) {
    try {
      long start = System.currentTimeMillis();

      IQRemediationRequest remediationRequest = new IQRemediationRequest();
      remediationRequest.setPackageUrl(packageUrl);

      Response response = prepareIqCall(apiUrl)
          .post(Entity.entity(remediationRequest.toJSONString(), MediaType.APPLICATION_JSON));
      String dataFromIQ = response.readEntity(String.class);
      long end = System.currentTimeMillis();
      logger.debug("*** iqServetPostCall (" + apiUrl + ") Response time: " + (end - start) + " ms");
      return dataFromIQ;
    } catch (Exception e) {
      logger.error(SonatypeConstants.ERR_IQ_API + apiUrl);
      logger.error("** Error message::" + e.getMessage());
      return ERROR_IQ_SERVER_API_CALL;
    }
  }
}
