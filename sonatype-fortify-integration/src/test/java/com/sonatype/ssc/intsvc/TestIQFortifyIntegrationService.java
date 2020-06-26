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
import java.io.IOException;

import java.util.Scanner;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.model.SSCApplicationRequest;
import com.sonatype.ssc.intsvc.model.SSCProject;
import com.sonatype.ssc.intsvc.util.ApplicationProperty;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.client.Entity;

import junit.framework.TestCase;

@RunWith(SpringJUnit4ClassRunner.class)
public class TestIQFortifyIntegrationService
    extends TestCase
{
  String[] projectName;

  String[] versionName;

  ApplicationProperties myProp = null;

  Client client;

  long[] projectId;

  String[] applicationName = null;

  int attributeId = 0;

  String attrJson = null;

  long[] applicationId;

  static int elementSize = 0;

  private static final Logger logger = Logger.getRootLogger();

  @Override
  @Before
  public void setUp() throws IOException {
    logger.info("inside set up .......");
    int index = 0;
    myProp = ApplicationProperty.loadProperties();
    client = ClientBuilder.newClient();
    HttpAuthenticationFeature feature = HttpAuthenticationFeature
        .basic(myProp.getSscServerUser(), myProp.getSscServerPassword());
    client.register(feature);

    projectName = new String[2];
    versionName = new String[2];
    applicationName = new String[2];
    projectId = new long[2];
    projectId = new long[2];

    Scanner sc = new Scanner(new File("TestData.txt"));
    while (sc.hasNext()) {
      String str = sc.nextLine();
      StringTokenizer st = new StringTokenizer(str, ",");
      while (st.hasMoreElements()) {
        projectName[index] = (String) st.nextElement();
        versionName[index] = (String) st.nextElement();
        String projectIdStr = (String) st.nextElement();
        projectId[index] = Long.parseLong(projectIdStr);
        applicationName[index] = (String) st.nextElement();

      }
      index++;
    }

    sc.close();
  }

  @Test

  public void test1GetNewSSCApplicationId() throws IOException {
    logger.info("test1GetNewSSCApplicationId .....");

    applicationId = new long[2];

    for (int index = 0; index < projectName.length; index++) {
      try {
        String apiURL = myProp.getSscServer() + SonatypeConstants.PROJECT_VERSION_URL;
        SSCApplicationRequest applicationRequest = new SSCApplicationRequest();
        SSCProject project = new SSCProject();
        project.setDescription(SonatypeConstants.SSC_APPLICATION_DESCRIPTION);
        project.setIssueTemplateId(SonatypeConstants.SSC_APPLICATION_TEMPLATE_ID);
        project.setName(projectName[index]);
        applicationRequest.setProject(project);
        applicationRequest.setActive(true);
        applicationRequest.setCommitted(true);
        applicationRequest.setName(versionName[index]);
        applicationRequest.setDescription(SonatypeConstants.SSC_APPLICATION_DESCRIPTION);
        applicationRequest.setStatus(SonatypeConstants.SSC_APPLICATION_ACTIVE);
        applicationRequest.setIssueTemplateId(SonatypeConstants.SSC_APPLICATION_TEMPLATE_ID);

        String applicationRequestJson = applicationRequest.toJSONString();

        WebTarget resource = client.target(apiURL);
        Response applicationCreateResponse = resource.request()
            .post(Entity.entity(applicationRequestJson, MediaType.APPLICATION_JSON));

        assertEquals("Expecting 201..But got different code-" + applicationCreateResponse.getStatus(), 201,
            applicationCreateResponse.getStatus());

        if (applicationCreateResponse.getStatus() != 201 && projectId[index] > 0) {
          project.setId(projectId[index]);

          applicationRequest.setProject(project);

          applicationRequestJson = applicationRequest.toJSONString();

          applicationCreateResponse = resource.request()
              .post(Entity.entity(applicationRequestJson, MediaType.APPLICATION_JSON));
        }

        String responseData = applicationCreateResponse.readEntity(String.class);

        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(responseData);
        JSONObject jData = (JSONObject) json.get(SonatypeConstants.DATA);
        applicationId[index] = (long) jData.get(SonatypeConstants.ID);
      }
      catch (Exception e) {
        logger.error(e.getMessage());
      }
    }
  }

  @Test
  public void test2UdateAttributes() throws Exception {
    logger.info("inside test2UdateAttributes .....");

    for (int index = 0; index < applicationId.length; index++) {
      try {
        StringBuilder apiURL = new StringBuilder(myProp.getSscServer())
            .append(SonatypeConstants.PROJECT_VERSION_URL).append(SonatypeConstants.SLASH)
            .append(applicationId[index])

            .append(SonatypeConstants.ATTRIBUTES);

        WebTarget resource = client.target(apiURL.toString());

        Response response = resource.request(MediaType.APPLICATION_JSON)
            .put(Entity.entity(SonatypeConstants.UPDATE_ATTRIBUTE_STRING, MediaType.APPLICATION_JSON));

        assertEquals("Expecting 200..But got different code-" + response.getStatus(), 200,
            response.getStatus());
      }
      catch (Exception e) {
        logger.error(e.getMessage());
      }
    }
  }

  @Test
  public void test5CommitApplication() throws Exception {
    logger.info("Inside test5CommitApplication .....");
    for (int index = 0; index < applicationId.length; index++) {

      StringBuilder apiURL = new StringBuilder(myProp.getSscServer()).append(SonatypeConstants.PROJECT_VERSION_URL)
          .append(SonatypeConstants.SLASH).append(applicationId[index]);

      WebTarget resource = client.target(apiURL.toString());

      Response response = resource.request(MediaType.APPLICATION_JSON)
          .put(Entity.entity(SonatypeConstants.COMMIT_JSON, MediaType.APPLICATION_JSON));

      assertEquals("Expecting 200..But got different code-" + response.getStatus(), 200, response.getStatus());
    }
  }
}
