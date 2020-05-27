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
package com.sonatype.ssc.integration.fortify.util;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;

import com.sonatype.ssc.integration.fortify.model.IQProperties;
import com.sonatype.ssc.integration.fortify.model.Remediation.RemediationResponse;
import com.sonatype.ssc.integration.fortify.model.VulnerabilityDetail.VulnDetailResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import com.sonatype.ssc.integration.fortify.constants.SonatypeConstants;
import com.sonatype.ssc.integration.fortify.model.IQProjectData;
import com.sonatype.ssc.integration.fortify.model.IQProjectVulnerability;

public class FortifyUtil
{
  private static final Logger logger = Logger.getRootLogger();

  private static final String CONT_SRC = "source";

  private static final String CONT_COMP_IDN = "componentIdentifier";

  private static final String CONT_CORD = "coordinates";

  private static final String CONT_CAT = "cataloged";

  private static final String CONT_WEB = "website";

  private static final String CONT_DESC = "description";

  private static final String CONT_EXP = "explanation";

  private static final String CONT_CWECWE = "cwecwe";

  private static final String CONT_CVSS2 = "cvecvss2";

  private static final String CONT_CVSS3 = "cvecvss3";

  private static final String CONT_CWEURL = "cweurl";

  private static final String CONT_PACK_URL = "packageUrl";

  private static final String CONT_ST_CVSS3 = "sonatypecvss3";

  @SuppressWarnings("unchecked")
  public String getInternalApplicationId(String jsonStr)
  {
    String internalAppId = "";
    if (jsonStr != null && jsonStr.length() > 0) {
      try {
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(jsonStr);
        JSONArray applications = (JSONArray) json.get("applications");
        Iterator<JSONObject> iterator = applications.iterator();
        while (iterator.hasNext()) {
          JSONObject dataObject = iterator.next();
          internalAppId = (String) dataObject.get("id");
        }
        return internalAppId;
      }
      catch (Exception e) {
        logger.error(SonatypeConstants.ERR_GET_INT_APP_ID + e.getMessage());
        return internalAppId;
      }
    }
    else {
      return internalAppId;
    }

  }

  private String getFileName(JSONObject dataObject) {
    String fileName = "";
    JSONArray fileArray = (JSONArray) dataObject.get("pathnames");
    if (!fileArray.isEmpty()) {
      for (int i = 0; i < fileArray.size(); i++) {
        fileName = (String) fileArray.get(i);
        if (fileName != null && fileName.length() > 0 && fileName.lastIndexOf('/') > 0) {
          fileName = fileName.substring(fileName.lastIndexOf('/') + 1);
        }
      }
    }
    return fileName;
  }

  @SuppressWarnings("unchecked")
  public String createJSON(IQProjectData iqPrjData,
                           List<IQProjectVulnerability> iqPrjVul,
                           String iqServerURL,
                           String loadLocation)
  {
    logger.debug(SonatypeConstants.MSG_WRITE_DATA);
    String fileName = "";
    JSONObject json = new JSONObject();
    json.put("engineVersion", "1.0");
    String evalDate = iqPrjData.getEvaluationDate();
    json.put("scanDate", evalDate);
    json.put("buildServer", iqPrjData.getProjectName());
    JSONArray list = new JSONArray();
    Iterator<IQProjectVulnerability> iterator = iqPrjVul.iterator();
    ArrayList<String> unqIdList = new ArrayList<>();
    //logger.debug("** In createJSON before while loop: " + iqPrjData.getProjectName());
    while (iterator.hasNext()) {
      IQProjectVulnerability iqProjectVul = iterator.next();
      //logger.debug("** In createJSON while loop: " + iqProjectVul.getUniqueId());

      JSONObject vul = new JSONObject();
      vul.put("uniqueId", iqProjectVul.getUniqueId());
      vul.put("issue", iqProjectVul.getIssue());
      vul.put("category", "Vulnerable OSS");
      //logger.debug("** In createJSON after category");
      vul.put("identificationSource", StringUtils.defaultString(iqProjectVul.getIdentificationSource()));
      //logger.debug("** In createJSON identificationSource: " + StringUtils.defaultString(iqProjectVul.getIdentificationSource()));
      vul.put("cveurl", StringUtils.defaultString(iqProjectVul.getCveurl()));
      vul.put("reportUrl", String.format("%s%s", iqServerURL, iqPrjData.getProjectIQReportURL()));
      vul.put("group", iqProjectVul.getGroup());
      vul.put("sonatypeThreatLevel", iqProjectVul.getSonatypeThreatLevel());

      if (iqProjectVul.getName() != null && iqProjectVul.getName().length() > 0) {
        vul.put("artifact", iqProjectVul.getName());
      }
      else {
        vul.put("artifact", iqProjectVul.getArtifact());
      }
      //logger.debug("** In createJSON before version");
      vul.put("version", StringUtils.defaultString(iqProjectVul.getVersion()));
      vul.put("fileName", StringUtils.defaultString(iqProjectVul.getFileName()));
      vul.put("matchState", StringUtils.defaultString(iqProjectVul.getMatchState()));
      //logger.debug("** In createJSON before qualifier");
//      vul.put("qualifier", StringUtils.defaultString(iqProjectVul.getQualifier()));
      vul.put("priority", StringUtils.defaultString(getPriority(iqProjectVul.getSonatypeThreatLevel())));
      //logger.debug("** In createJSON before customstatus");
      vul.put("customStatus", StringUtils.defaultString(iqProjectVul.getCustomStatus()));
      //logger.debug("** In createJSON before classifier");
      vul.put("classifier", StringUtils.defaultString(iqProjectVul.getClassifier()));
      //logger.debug("** In createJSON before effect");
//      vul.put("effectiveLicense", StringUtils.defaultString(iqProjectVul.getEffectiveLicense()));

      //logger.debug("** In createJSON before parseRemediationResponse");

      // TODO:  REMEDIATION COMMENTED OUT FOR SPEED
      //vul.put("recommendedVersion", StringUtils.defaultString(parseRemediationResponse(iqProjectVul.getRemediationResponse(), iqProjectVul)));

      vul.put(CONT_PACK_URL, StringUtils.defaultString(iqProjectVul.getPackageUrl()));

      //logger.debug("** In createJSON before getVulnDetail **");
//      Map<String, String> compDataMap = getCompData(iqProjectVul, iqProjectVul.getCompReportDetails());
//      vul.put(CONT_CAT, compDataMap.get(CONT_CAT));
//      vul.put(CONT_WEB, compDataMap.get(CONT_WEB));
//
      try {
        //logger.debug("** right before set vulnDetail");
        VulnDetailResponse vulnDetail = iqProjectVul.getVulnDetail();
        if (vulnDetail != null) {
          vul.put(CONT_SRC, vulnDetail.getSource().getLongName());

          //logger.debug("** In createJSON before buildDescription 1");
          String combinedDesc = buildDescription(vulnDetail, iqProjectVul);
          vul.put("vulnerabilityAbstract", combinedDesc);

          //logger.debug("** In createJSON before buildDescription 2");
          vul.put(CONT_DESC, combinedDesc);
          // TODO: Stop making the assumption on the order of this array

          if (vulnDetail.getWeakness() != null && !vulnDetail.getWeakness().getCweIds().isEmpty()) {
            vul.put(CONT_CWECWE, vulnDetail.getWeakness().getCweIds().get(0).getId());
            vul.put(CONT_CWEURL, vulnDetail.getWeakness().getCweIds().get(0).getUri());
          }
          // TODO: Set default string
          //logger.debug("** In createJSON severity scores: " + vulnDetail.getSeverityScores().get(0));
//        if (vulnDetail.getSeverityScores() != null && !vulnDetail.getSeverityScores().isEmpty() && vulnDetail.getSeverityScores().size() > 1) {

          vul.put(CONT_CVSS2, StringUtils.defaultIfBlank(vulnDetail.getSeverityScores().get(0).getScore().toString(), "N/A"));
          vul.put(CONT_CVSS3, StringUtils.defaultIfBlank(vulnDetail.getSeverityScores().get(1).getScore().toString(), "N/A"));

          if (vulnDetail.getMainSeverity() != null) {
            vul.put(CONT_ST_CVSS3, StringUtils.defaultIfBlank(vulnDetail.getMainSeverity().getScore().toString(), "N/A"));
          }
        }
        else {
          vul.put("vulnerabilityAbstract", "Vulnerability detail not available.");
        }
      } catch (Exception e) {
        logger.error(e.getMessage());
      }
//        vul.put("componentRemediationResults", iqProjectVul.getComponentRemediationResults());
        list.add(vul);
    }
    json.put("findings", list);
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
//    logger.info("** In createJSON in buildDescription: " + vulnDetail.toString()) ;
    String desc = "";
    logger.info("** In createJSON in buildDescription");
    // TODO: Format the markdown for SSC

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
    // TODO: Format the remediation results to give a single version
    return desc;

  }

  public String parseRemediationResponse(RemediationResponse response, IQProjectVulnerability iqProjectVul) {
    if (response.getRemediation().getVersionChanges() != null && response.getRemediation().getVersionChanges().size() > 0) {
      logger.debug(("*** getVersionChanges: ") + response.getRemediation().getVersionChanges().toString());
      logger.debug("*** Attempting to get Recommended Version: ");
      // TODO: only getting the first instance which in development, is 'next-no-violations'
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

  @SuppressWarnings("unchecked")
  public IQProjectData getIQProjectData(String jsonStr, String prjStage, String prjName)
  {
    logger.info(SonatypeConstants.MSG_GET_IQ_DATA);
    IQProjectData iqProjectData = new IQProjectData();
    try {
      JSONParser parser = new JSONParser();
      JSONArray json = (JSONArray) parser.parse(jsonStr);
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
      return iqProjectData;
    }
    catch (Exception e) {
      logger.error("Error in getting internal application id from IQ: " + e.getMessage());
      return iqProjectData;
    }
  }

  public Map<String, String> getCompData(IQProjectVulnerability iqProjectVul, String compData) {
    Map<String, String> compDataMap = new LinkedHashMap<>();
    try {
      JSONParser parser = new JSONParser();
      JSONObject json = (JSONObject) parser.parse(compData);

      long diff = (new Date()).getTime() - (new Date((Long) json.get("catalogDate"))).getTime();
      long daysDiff = TimeUnit.DAYS.convert(diff, TimeUnit.MILLISECONDS);
      String cataloged = getCatalogedDuration(daysDiff);
      if (cataloged.length() > 0) {
        compDataMap.put(CONT_CAT, cataloged);
      }
      else {
        compDataMap.put(CONT_CAT, "");
      }

      String website = (String) json.get(CONT_WEB);
      if (website != null && website.length() > 0) {
        compDataMap.put(CONT_WEB, website);
      }
      else {
        compDataMap.put(CONT_WEB, "");
      }

      return compDataMap;
    }
    catch (Exception e) {
      logger.error("Error in getCompData: " + e.getMessage());
      return compDataMap;
    }
  }

  private String getCatalogedDuration(long daysDiff) {
    String cataloged = "";
    long years = daysDiff / 365;

    if (years > 0) {
      cataloged = Long.toString(years) + " years ago";
    }
    else {
      long months = daysDiff / 30;
      if (months > 0) {
        cataloged = Long.toString(months) + " months ago";
      }
      else {
        cataloged = Long.toString(daysDiff) + " days ago";
      }
    }
    return cataloged;
  }

  public Map<String, String> getDataFromHTML(String htmlData) {

    Map<String, String> htmlDataMap = new LinkedHashMap<>();
    Document doc = Jsoup.parse(htmlData);
    String source = null;

    Elements divElms = doc.select("dt:containsOwn(Source)");
    if (isElementNotNull(divElms)) {

      source = divElms.get(0).nextElementSibling().text();

      htmlDataMap.put(CONT_SRC, source);
    }
    else {
      htmlDataMap.put(CONT_SRC, "");
    }
    Elements divElmsDesc;

    if (source != null && (!source.isEmpty()) && source.contains("Sonatype")) {
      logger.debug("** SOURCE: " + source);
      divElmsDesc = doc.select("dt:containsOwn(Explanation)");
    } else {
      divElmsDesc = doc.select("dt:containsOwn(Description from CVE)");
    }

    if (isElementNotNull(divElmsDesc)) {
      htmlDataMap.put(CONT_DESC, divElmsDesc.get(0).nextElementSibling().text());
    }
    else {
      htmlDataMap.put(CONT_DESC, "No description provided in the vulnerability.");
    }

    Elements divElmsExpl = doc.select("dt:containsOwn(Explanation)");
    if (isElementNotNull(divElmsExpl)) {
      htmlDataMap.put(CONT_EXP, divElmsExpl.get(0).nextElementSibling().text());
    }
    else {
      htmlDataMap.put(CONT_EXP, "");
    }

    Elements divElmsWeakness = doc.select("dd:containsOwn(CWE)");

    if (isElementNotNull(divElmsWeakness)) {
      String cweText = divElmsWeakness.get(0).select("a").first().text();
      String cweUrl = divElmsWeakness.get(0).select("a").first().attr("href");
      logger.debug("** CWE TEXT: " + cweText);
      logger.debug("** CWE URL: " + cweUrl);
      htmlDataMap.put(CONT_CWECWE, cweText);
      htmlDataMap.put(CONT_CWEURL, cweUrl);
    }
    else {
      htmlDataMap.put(CONT_CWECWE, "");
      htmlDataMap.put(CONT_CWEURL, "N/A");
    }


    Elements divElmsSev = doc.select("dt:containsOwn(Severity)");
    htmlDataMap.put(CONT_CVSS2, "");
    htmlDataMap.put(CONT_CVSS3, "");
    htmlDataMap.put(CONT_ST_CVSS3, "");
    if (isElementNotNull(divElmsSev)) {
      String sev = divElmsSev.get(0).nextElementSibling().html();
      getCVSRatingData(htmlDataMap, sev);
    }
    return htmlDataMap;
  }

  private void getCVSRatingData(Map<String, String> htmlDataMap, String sev) {
    logger.debug("** Severity String: " + sev);
    StringTokenizer st = new StringTokenizer(sev, "<br>");

    while (st.hasMoreTokens()) {
      String str = st.nextToken();
      if (str.indexOf("CVE CVSS 2.0:") >= 0) {
//        logger.debug("** CVE CVSS 2.0: " + (str.substring(str.indexOf(':') + 2)).trim());
        htmlDataMap.put(CONT_CVSS2, (str.substring(str.indexOf(':') + 2)).trim());
      }

      if (str.indexOf("CVE CVSS 3.0:") >= 0) {
//        logger.debug("** CVE CVSS 3.0: " + (str.substring(str.indexOf(':') + 2)).trim());
        htmlDataMap.put(CONT_CVSS3, (str.substring(str.indexOf(':') + 2)).trim());
      }

      if (str.indexOf("Sonatype CVSS 3.0:") >= 0) {
//        logger.debug("** Sonatype CVSS 3.0: " + (str.substring(str.indexOf(':') + 2)).trim());
        htmlDataMap.put(CONT_ST_CVSS3, (str.substring(str.indexOf(':') + 2)).trim());
      }
    }
  }

  private boolean isElementNotNull(Elements ele) {

    if (ele != null && (!ele.isEmpty())) {
      return true;
    }

    return false;

  }

  private String getReportId(String reportUrl) {
    String reportId = "";
    reportId = reportUrl.substring(reportUrl.indexOf("/report/") + 8, reportUrl.length());
    return reportId;
  }

}
