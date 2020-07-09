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
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.IQProjectData;
import com.sonatype.ssc.intsvc.model.IQRemediationRequest;
import com.sonatype.ssc.intsvc.model.PolicyViolation.PolicyViolationResponse;
import com.sonatype.ssc.intsvc.model.Remediation.RemediationResponse;
import com.sonatype.ssc.intsvc.model.VulnerabilityDetail.VulnDetailResponse;

/**
 * Utility to read IQ REST APIs results
 */
public class IQClient
{
  private static final Logger logger = Logger.getLogger("IQClient");

  private static final String ERROR_IQ_SERVER_API_CALL = "Error in call to IQ Server";

  // https://help.sonatype.com/iqserver/automating/rest-apis/application-rest-apis---v2#ApplicationRESTAPIs-v2-Step5-UpdateApplicationInformation
  private static final String API_APPLICATIONS_BY_PUBLIC_ID = "api/v2/applications?publicId=%s";

  // https://help.sonatype.com/iqserver/automating/rest-apis/report-related-rest-apis---v2#Report-relatedRESTAPIs-v2-reportId
  private static final String API_REPORTS_APPLICATIONS = "api/v2/reports/applications/%s";

  // https://help.sonatype.com/iqserver/automating/rest-apis/report-related-rest-apis---v2#Report-relatedRESTAPIs-v2-PolicyViolationsbyReportRESTAPI(v2)
  private static final String API_POLICY_VIOLATIONS_BY_REPORT = "api/v2/applications/%s/reports/%s/policy";

  private static final String IQ_REPORT_URL = "assets/index.html#/applicationReport";

  // https://help.sonatype.com/iqserver/automating/rest-apis/vulnerability-details-rest-api---v2
  private static final String API_VULNERABILY_DETAILS = "api/v2/vulnerabilities/%s";

  // https://help.sonatype.com/iqserver/automating/rest-apis/component-details-rest-api---v2
  private static final String API_COMPONENT_DETAILS = "api/v2/components/details";

  private static final String IQ_VULNERABILITY_DETAIL_URL = "assets/index.html#/vulnerabilities/%s";

  // https://help.sonatype.com/iqserver/automating/rest-apis/component-remediation-rest-api---v2
  private static final String API_COMPONENT_REMEDIATION = "api/v2/components/remediation/application/%s?stageId=%s";

  private final ApplicationProperties appProp;

  public IQClient(ApplicationProperties appProp) {
    this.appProp = appProp;
  }

  private String getApiUrl(String api, Object...params) {
    return params == null ? (appProp.getIqServer() + api) : (appProp.getIqServer() + String.format(api, params)); 
  }

  /**
   * <a href="https://help.sonatype.com/iqserver/automating/rest-apis/application-rest-apis---v2#ApplicationRESTAPIs-v2-Step5-UpdateApplicationInformation">GET application info</a>
   * 
   * @param publicId the application public id
   * @return corresponding internal id
   */
  public String getInternalApplicationId(String publicId) {
    String jsonStr = callIqServerGET(API_APPLICATIONS_BY_PUBLIC_ID, publicId);
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

  /**
   * <a href="https://help.sonatype.com/iqserver/automating/rest-apis/report-related-rest-apis---v2#Report-relatedRESTAPIs-v2-PolicyViolationsbyReportRESTAPI(v2)">Policy Violations by Report</a>
   * @param publicId the application public id
   * @param reportId the report id
   * @return the policy violations response
   * @throws JsonProcessingException 
   * @throws JsonMappingException 
   */
  public PolicyViolationResponse getPolicyViolationsByReport(String publicId, String reportId)
      throws JsonMappingException, JsonProcessingException {
    String result = callIqServerGET(API_POLICY_VIOLATIONS_BY_REPORT, publicId, reportId);
    return (new ObjectMapper()).readValue(result, PolicyViolationResponse.class);
  }

  public String getIqReportUrl(String appId, String reportId, String reportType) {
    return IQ_REPORT_URL + '/' + appId + '/' + reportId + '/' + reportType;
  }

  private String getReportId(String reportUrl) {
    return reportUrl.substring(reportUrl.indexOf("/report/") + 8, reportUrl.length());
  }

  /**
   * <a href="https://help.sonatype.com/iqserver/automating/rest-apis/report-related-rest-apis---v2#Report-relatedRESTAPIs-v2-reportId">GET report ids</a>
   * 
   * @param internalAppId the internal app id
   * @param prjStage the requested stage
   * @param prjName the project name to put in the return data
   * @return project data
   */
  public IQProjectData getIQProjectData(String internalAppId, String prjStage, String prjName)
  {
    logger.info(SonatypeConstants.MSG_GET_IQ_DATA);
    String jsonStr = callIqServerGET(API_REPORTS_APPLICATIONS, internalAppId);

    IQProjectData iqProjectData = new IQProjectData();
    iqProjectData.setInternalAppId(internalAppId);
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
    return iqProjectData;
  }

  public String getVulnDetailURL(String vulnerabilityId) {
    // Update to new vulnerability rest API
    // GET /api/v2/vulnerabilities/{vulnerabilityId}
    return getApiUrl(IQ_VULNERABILITY_DETAIL_URL, vulnerabilityId);
  }

  /**
   * <a href="https://help.sonatype.com/iqserver/automating/rest-apis/vulnerability-details-rest-api---v2">Vulnerability details</a>
   * @param vulnerabilityId the vulnerability id
   * @return the vulnerability details (or null)
   * @throws JsonProcessingException 
   * @throws JsonMappingException 
   */
  public VulnDetailResponse getVulnDetails(String vulnerabilityId)
      throws JsonMappingException, JsonProcessingException {
    String result = callIqServerGET(API_VULNERABILY_DETAILS, vulnerabilityId);
    if (!"UNKNOWN".equalsIgnoreCase(result)) {
      return (new ObjectMapper()).readValue(result, VulnDetailResponse.class);
    }
    return null;
  }

  /**
   * <a href="https://help.sonatype.com/iqserver/automating/rest-apis/component-details-rest-api---v2">Component details</a>
   * 
   * @param packageUrl component packageUrl
   * @return the json result of API call
   */
  public String getComponentDetails(String packageUrl) {
    return callIqServerPOSTpurl(packageUrl, API_COMPONENT_DETAILS);
  }

  /**
   * <a href="https://help.sonatype.com/iqserver/automating/rest-apis/component-remediation-rest-api---v2">Component Remediation</a>
   * 
   * @param appInternalId the application internal id
   * @param stageId the stage id
   * @param packageUrl component packageUrl
   * @return the remediation response
   * @throws JsonProcessingException 
   * @throws JsonMappingException 
   */
  public RemediationResponse getCompRemediation(String appInternalId, String stageId, String packageUrl)
      throws JsonMappingException, JsonProcessingException {
    // POST /api/v2/components/remediation/application/{applicationInternalId}?stageId={stageId}
    String result = callIqServerPOSTpurl(packageUrl, API_COMPONENT_REMEDIATION, appInternalId, stageId);
    return (new ObjectMapper()).readValue(result, RemediationResponse.class);
  }

  private String callIqServerGET(String api, Object...params) {
    return iqServerCall(null, api, params);
  }

  private String callIqServerPOSTpurl(String packageUrl, String api, Object...params) {
      IQRemediationRequest remediationRequest = new IQRemediationRequest();
      remediationRequest.setPackageUrl(packageUrl);
      return iqServerCall(remediationRequest.toJSONString(), api, params);
  }

  private String iqServerCall(String post, String api, Object...params) {
    long start = System.currentTimeMillis();
    String apiUrl = getApiUrl(api, params).replaceAll(" ", "%20");

    try {
      Client client = ClientBuilder.newClient();
      Feature auth = HttpAuthenticationFeature.basic(appProp.getIqServerUser(), appProp.getIqServerPassword());
      client.register(auth);
      Builder builder = client.target(apiUrl).request(MediaType.APPLICATION_JSON);

      Response response;
      if (post == null) {
        response = builder.get();
      } else {
        response = builder.post(Entity.entity(post, MediaType.APPLICATION_JSON));
      }
      String dataFromIQ = response.readEntity(String.class);

      long end = System.currentTimeMillis();
      logger.debug("*** call (" + apiUrl + ") Response time: " + (end - start) + " ms");

      if (response.getStatus() == 404) {
        return "UNKNOWN";
      }

      return dataFromIQ;
    } catch (Exception e) {
      logger.error(SonatypeConstants.ERR_IQ_API + apiUrl);
      logger.debug("Error message::" + e.toString());
      return ERROR_IQ_SERVER_API_CALL;
    }
  }
}
