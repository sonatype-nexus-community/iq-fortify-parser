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

import java.util.Iterator;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.IQProjectData;
import com.sonatype.ssc.intsvc.model.IQRemediationRequest;

/**
 * utility to read IQ REST APIs results
 */
public class IQClient
{
  private static final Logger logger = Logger.getLogger("IQClient");

  private static final String ERROR_IQ_SERVER_API_CALL = "Error in call to IQ Server";

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
    logger.debug("** vulnDetailURL: " + vulnDetailURL);
    return vulnDetailURL;
  }

  public String getVulnDetail(String CVE, ApplicationProperties appProp) {
    String vulnDetailRest = appProp.getIqServer() + SonatypeConstants.IQ_VULNERABILITY_DETAIL_REST + CVE;
    logger.debug("** vulnDetailURL: " + vulnDetailRest);
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
