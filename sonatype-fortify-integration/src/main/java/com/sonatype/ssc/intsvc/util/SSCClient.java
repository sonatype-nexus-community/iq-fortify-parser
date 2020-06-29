/*
 * Copyright (c) 2020-present Sonatype, Inc. All rights reserved.
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

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.log4j.Logger;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPart;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.media.multipart.file.FileDataBodyPart;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.sonatype.ssc.intsvc.ApplicationProperties;
import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.SSCApplicationRequest;
import com.sonatype.ssc.intsvc.model.SSCProject;

public class SSCClient {
  private static final Logger logger = Logger.getLogger("SSCClient");

  private final String sscServerUrl;

  private final HttpAuthenticationFeature sscAuth;

  public SSCClient(ApplicationProperties appProp) {
    sscServerUrl = appProp.getSscServer();
    sscAuth = HttpAuthenticationFeature.basic(appProp.getSscServerUser(), appProp.getSscServerPassword());
  }

  public long getSSCApplicationId(String application, String version) {
    logger.info(SonatypeConstants.MSG_READ_SSC);

    long applicationId = 0;
    String apiURL = sscServerUrl + SonatypeConstants.SSC_PROJECT_URL + application + "%22";
    logger.debug("SSC get application info apiURL: " + apiURL);

    String strContent = sscServerGetCall(apiURL);
    if (strContent.equalsIgnoreCase("ERROR_SSC_SERVER_API_CALL")) {
      return -1;
    }
    else {
      try {

        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(strContent);
        JSONArray jData = (JSONArray) json.get("data");
        @SuppressWarnings("unchecked")
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
  public long getNewSSCApplicationId(String projectName, String version) {

    logger.info(SonatypeConstants.MSG_SSC_APP_CRT);

    long applicationId = 0;
    long projectId = 0;
    try {

      String apiURL = sscServerUrl + SonatypeConstants.SSC_PROJECT_VERSION_URL;

      SSCProject project = new SSCProject();
      project.setDescription(SonatypeConstants.SSC_APPLICATION_DESCRIPTION);
      project.setIssueTemplateId(SonatypeConstants.SSC_APPLICATION_TEMPLATE_ID);
      project.setCreatedBy(SonatypeConstants.SSC_APPLICATION_CREATED_BY);
      project.setName(projectName);

      SSCApplicationRequest applicationRequest = new SSCApplicationRequest();
      applicationRequest.setProject(project);
      applicationRequest.setActive(true);
      applicationRequest.setCommitted(true);
      applicationRequest.setName(version);
      applicationRequest.setDescription(SonatypeConstants.SSC_APPLICATION_DESCRIPTION);
      applicationRequest.setStatus(SonatypeConstants.SSC_APPLICATION_ACTIVE);
      applicationRequest.setIssueTemplateId(SonatypeConstants.SSC_APPLICATION_TEMPLATE_ID);

      String applicationRequestJson = applicationRequest.toJSONString();

      Builder sscCallBuilder = prepareSscCall(apiURL);
      Response applicationCreateResponse = sscCallBuilder
          .post(Entity.entity(applicationRequestJson, MediaType.APPLICATION_JSON));

      if (applicationCreateResponse.getStatus() != 201) { // check whether application created or not-201 means
        // application created
        projectId = getProjectId(projectName); // if already application exists fetch the projectId
        if (projectId > 0) {
          project.setId(projectId);
          applicationRequest.setProject(project);
          applicationRequestJson = applicationRequest.toJSONString();
          applicationCreateResponse = sscCallBuilder
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
        updateApplication(applicationId);
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

  private void updateApplication(long applicationId) {
    try {
      if (updateAttributes(applicationId)) {
        commitApplication(applicationId);
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
   * @param applicationId long
   * @return boolean status
   */
  private boolean updateAttributes(long applicationId) {

    logger.debug("Start of Method updateAttributes.......");

    try {
      String apiURL = sscServerUrl + SonatypeConstants.SSC_PROJECT_VERSION_URL + '/' + applicationId
          + SonatypeConstants.ATTRIBUTES;

      Response response = prepareSscCall(apiURL)
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
   * @param applicationId long
   * @return boolean
   */
  private boolean commitApplication(long applicationId) {
    logger.debug("Start of Method commitApplication..");

    String apiURL = sscServerUrl + SonatypeConstants.SSC_PROJECT_VERSION_URL + '/' + applicationId;

    Response response = prepareSscCall(apiURL)
        .put(Entity.entity(SonatypeConstants.COMMIT_JSON, MediaType.APPLICATION_JSON));

    logger.debug("End of Method commitApplication: " + response.getStatus());
    return response.getStatus() == 200;
  }

  private long getProjectId(String applicationName) {
    logger.debug("Start of Method getProjectId........");

    long projectId = 0;

    String apiURL = sscServerUrl + SonatypeConstants.PROJECT_URL;

    String dataFromSSC = sscServerGetCall(apiURL);

    try {
      JSONParser parser = new JSONParser();
      JSONObject json = (JSONObject) parser.parse(dataFromSSC);
      JSONArray jData = (JSONArray) json.get(SonatypeConstants.DATA);
      @SuppressWarnings("unchecked")
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

  public boolean uploadVulnerabilityByProjectVersion(final long entityIdVal, final File file)
      throws IOException
  {
    Client client = ClientBuilder.newBuilder().register(MultiPartFeature.class).build();

    try {
      logger.debug("Uploading data into SSC from file " + file);

      client.register(sscAuth);

      String apiURL = sscServerUrl + SonatypeConstants.FILE_UPLOAD_URL;
      WebTarget resource = client.target(apiURL + getFileToken());

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
      deletetFileToken();
    }

  }

  /**
   * This method fetches the file token from fortify server
   *
   * @param appProp IQProperties .
   * @return String.
   */
  private String getFileToken() throws ParseException {

    String apiURL = sscServerUrl + SonatypeConstants.FILE_TOKEN_URL;

    Response applicationCreateResponse = prepareSscCall(apiURL)
        .post(Entity.entity(SonatypeConstants.FILE_TOKEN_JSON, MediaType.APPLICATION_JSON));

    String responseData = applicationCreateResponse.readEntity(String.class);

    JSONParser parser = new JSONParser();
    JSONObject json = (JSONObject) parser.parse(responseData);
    JSONObject jData = (JSONObject) json.get(SonatypeConstants.DATA);
    return (String) jData.get(SonatypeConstants.TOKEN);

  }

  /**
   * This method deletes  the file token from fortify server
   *
   * @param  appProp IQProperties .
   * @return String.
   * @throws Exception, JsonProcessingException.
   */
  private boolean deletetFileToken() {

    try {
      String apiURL = sscServerUrl + SonatypeConstants.FILE_TOKEN_URL;

      Response applicationCreateResponse = prepareSscCall(apiURL).delete();
      logger.debug("applicationCreateResponse:::" + applicationCreateResponse);
      return true;
    }
    catch (Exception e) {
      logger.error("Exception occured while deleting the  file token::" + e.getMessage());
      return false;

    }

  }

  private WebTarget prepareSscTarget(String apiUrl) {
    apiUrl = apiUrl.replaceAll(" ", "%20");
    Client client = ClientBuilder.newClient();
    client.register(sscAuth);
    return client.target(apiUrl);
  }

  private Builder prepareSscCall(String apiUrl) {
    return prepareSscTarget(apiUrl).request(MediaType.APPLICATION_JSON);
  }

  private String sscServerGetCall(String apiUrl) {
    try {
      Response response = prepareSscCall(apiUrl).get();
      return response.readEntity(String.class);
    }
    catch (Exception e) {
      logger.error(SonatypeConstants.ERR_SSC_API + apiUrl);
      logger.debug("Error message::" + e.getMessage());
      return "ERROR_SSC_SERVER_API_CALL";
    }
  }
}
