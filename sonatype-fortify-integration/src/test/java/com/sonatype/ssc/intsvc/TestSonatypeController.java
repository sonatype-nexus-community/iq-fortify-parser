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
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sonatype.ssc.intsvc.service.IQFortifyIntegrationService;
import com.sonatype.ssc.intsvc.util.ApplicationPropertiesLoader;
import com.sonatype.ssc.model.Finding;
import com.sonatype.ssc.model.Scan;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Integration Test: checks that the integration service extracts from IQ and loads to SSC as expected.
 * 
 * Requirements:
 * 1. load src/test/resources/Sonatype-Fortify-integration-sample-application-bom.xm into IQ
 * as "build" stage of an application with "sonatype-fortify-integration-sample-application" public id
 * and default policy
 * 2. update "iqapplication.properties" iqserver.* and sscserver.* properties
 * 
 * Then run the IT, either through your IDE or with "mvn -Prun-its verify"
 * 
 * It will launch the integration service to extract violations from IQ and upload to SSC, and check
 * that extracted data (in generated file in base directory) matches expected content (.json file in SBOM
 * directory).
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = TestApplication.class)
@ContextConfiguration(classes = IQFortifyIntegrationService.class)
public class TestSonatypeController
{
  private static final String SCAN_JSON_FILENAME = "sonatype-fortify-integration-sample-application_build.json";
  @Autowired
  private IQFortifyIntegrationService iqFortifyIntgSrv;

  private static final Logger logger = Logger.getRootLogger();

  @Test
  public void testStartScanLoad() throws Exception {
    logger.addAppender(new ConsoleAppender(new PatternLayout("%d{ISO8601} [%t] %-5p %c %x - %m%n")));
    ApplicationProperties myProp = null;
    try {
      myProp = ApplicationPropertiesLoader.loadProperties();

      assertNotNull("Iq Server field is null...", myProp.getIqServer());
      assertNotNull("Iq Server password field is null...", myProp.getIqServerPassword());
      assertNotNull("Load Location field is null...", myProp.getLoadLocation());
      assertNotNull("Fortify Server field is  null...", myProp.getSscServer());
      assertNotNull("Fortify Token field is  null...", myProp.getSscServerToken());
      assertNotNull("Load location field is  null...", myProp.getLoadLocation());
    }
    catch (FileNotFoundException e) {
      logger.error(e.getMessage());
    }
    catch (IOException e) {
      logger.error("IOException exception:" + e.getMessage());
    }

    if (myProp.getMissingReqProp()) {
      logger.fatal("missing required property, stopping test");
      return;
    }

    File jsonFile = new File(SCAN_JSON_FILENAME);
    if (jsonFile.exists()) {
      logger.info("Deleting existing " + SCAN_JSON_FILENAME + ": " + jsonFile.delete());
    }

    try {
      iqFortifyIntgSrv.startLoad(myProp);
    }
    catch (IOException e) {
      logger.error("issue while running startLoad", e);
    }

    // check generated sonatype-fortify-integration-sample-application_build.json
    // content against reference
    // src/test/resources/Sonatype-Fortify-integration-sample-application-scan.json
    if (!jsonFile.exists()) {
      logger.error("Cannot find " + SCAN_JSON_FILENAME + " for integration test");
      fail("Cannot find " + SCAN_JSON_FILENAME + " for integration test: issues when calling IQ or SSC?");
    }
    logger.info("Checking " + SCAN_JSON_FILENAME + " content (" + jsonFile.length() + " bytes)");
    JSONObject json = (JSONObject) new JSONParser().parse(new FileReader(jsonFile));

    File jsonReferenceFile = new File("src/test/resources/Sonatype-Fortify-integration-sample-application-scan.json");

    // read and reformat json file
    reformatScanJson(jsonFile, new File("target/scan-effective.json"));
    reformatScanJson(jsonReferenceFile, new File("target/scan-reference.json"));

    JSONObject ref = (JSONObject) new JSONParser().parse(new FileReader(jsonReferenceFile));

    String current = null;
    try {
      JSONArray findings = (JSONArray) json.remove("findings");
      JSONArray refFindings = (JSONArray) ref.remove("findings");

      // compare base scan fields
      // obviously not reproducible field: TODO check format
      json.remove("scanDate");
      ref.remove("scanDate");
      // check other fields
      @SuppressWarnings("unchecked")
      Set<Map.Entry<String, Object>> values = ref.entrySet();
      for(Map.Entry<String,Object> entry: values) {
        assertEquals(entry.getKey(), entry.getValue(), json.remove(entry.getKey()));
      }

      // compare findings
      logger.info("Checking " + findings.size() + " findings");
      // prepare a map fo reference findings indexed on fileName
      Map<String, JSONObject> findingsMap = new HashMap<>();
      for(Object o: refFindings) {
        JSONObject finding = (JSONObject) o;
        String key = getFindingKey(finding);
        Object prev = findingsMap.put(key, finding);
        if (prev != null) {
          logger.warn("Findings contains multiple entries with fileName = " + key);
        }
      }
      for(Object o: findings) {
        JSONObject finding = (JSONObject) o;
        current = getFindingKey(finding);
        JSONObject refFinding = findingsMap.remove(current);
        if (refFinding == null) {
          assertTrue("Finding with key = " + current, false);
        }
        compareFinding(refFinding, finding);
      }
      current = null;

      assertEquals("unexpected missing findings: " + findingsMap, 0, findingsMap.size());
      logger.info("Findings ok");

      assertEquals("unexpected additional fields: " + json, 0, json.size());
      
    } catch (AssertionError ae) {
      if (current == null) {
        logger.error("there was a failure during checks: see JUnit output");
      } else {
        logger.error("there was a failure while checking finding with fileName = " + current);
      }
      throw ae;
    }
  }

  private void reformatScanJson(File source, File dest) throws IOException {
    ObjectMapper mapper = new ObjectMapper();

    // read
    Scan effectiveScan = mapper.readValue(source, Scan.class);

    // work-around non-repeatable parts
    // TODO scanDate
    for (Finding f: effectiveScan.getFindings()) {
      f.setUniqueId("{violation id (hex)}");
      f.setReportUrl(f.getReportUrl().replaceAll("sample-application/[0-9a-f]+/", "sample-application/{reportId}/"));
      String vulnAbstract = f.getVulnerabilityAbstract();
      vulnAbstract = vulnAbstract.substring(0, vulnAbstract.indexOf("\\r\\n\\r\\n") + 8) + "Description...";
      f.setVulnerabilityAbstract(vulnAbstract);
    }

    // write
    mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
    mapper.writeValue(dest, effectiveScan);
  }

  private void compareFinding(JSONObject refFinding, JSONObject finding) {
    // obviously not reproducible field: TODO check format
    refFinding.remove("uniqueId");
    finding.remove("uniqueId");
    // simplified comparison
    refFinding.remove("vulnerabilityAbstract");
    finding.remove("vulnerabilityAbstract");

    finding.put("reportUrl", finding.get("reportUrl").toString().replaceAll("sample-application/[0-9a-f]+/", "sample-application/{reportId}/"));

    // TODO check that cveurl and reportUrl start with IQ url

    @SuppressWarnings("unchecked")
    Set<Map.Entry<String, Object>> values = refFinding.entrySet();
    for(Map.Entry<String,Object> entry: values) {
      assertEquals(entry.getKey(), entry.getValue(), finding.remove(entry.getKey()));
    }
  }

  private String getFindingKey(JSONObject json) {
    return (String) json.get("issue") + " - " + (String) json.get("fileName");
  }
}
