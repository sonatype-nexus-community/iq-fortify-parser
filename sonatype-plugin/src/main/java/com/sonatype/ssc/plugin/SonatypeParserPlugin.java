package com.sonatype.ssc.plugin;

/**
 * (c) Copyright Sonatype Inc. 2018
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import com.sonatype.ssc.model.DateDeserializer;
import com.sonatype.ssc.model.DecimalConverter;
import com.sonatype.ssc.model.Finding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;

import static com.sonatype.ssc.plugin.SonatypeVulnAttribute.*;

public class SonatypeParserPlugin implements ParserPlugin<SonatypeVulnAttribute> {
  private static final Logger LOG = LoggerFactory.getLogger(SonatypeParserPlugin.class);

  private static final JsonFactory JSON_FACTORY;
  private static final DateDeserializer DATE_DESERIALIZER = new DateDeserializer();

  static {
    JSON_FACTORY = new JsonFactory();
    JSON_FACTORY.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
  }

  @Override
  public void start() throws Exception {
    LOG.info("SonatypeParserPlugin plugin is starting");
  }

  @Override
  public void stop() throws Exception {
    LOG.info("SonatypeParserPlugin plugin is stopping");
  }

  @Override
  public Class<SonatypeVulnAttribute> getVulnerabilityAttributesClass() {
    return SonatypeVulnAttribute.class;
  }

  @Override
  public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder)
      throws ScanParsingException, IOException {
    LOG.info("SonatypeParserPlugin scan is starting, sessionId {}", scanData.getSessionId());
    parseJson(scanData, scanBuilder, this::parseScanInternal);
    LOG.info("SonatypeParserPlugin scan done, sessionId {}", scanData.getSessionId());
    // complete scan building
    scanBuilder.completeScan();
  }

  private void parseScanInternal(final ScanData scanData, final ScanBuilder scanBuilder, final JsonParser jsonParser)
      throws IOException, ScanParsingException {
    // load data from top-level object fields
    while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
      final VulnAttribute vulnAttr = VulnAttribute.get(jsonParser.getCurrentName());
      jsonParser.nextToken();
      if (vulnAttr == null) {
        skipChildren(jsonParser);
        continue;
      }

      switch (vulnAttr) {
      case SCAN_DATE:
        scanBuilder.setScanDate(DATE_DESERIALIZER.convert(jsonParser.getText()));
        break;

      case ENGINE_VERSION:
        scanBuilder.setEngineVersion(jsonParser.getText());
        break;

//      case ELAPSED:
//        scanBuilder.setElapsedTime(jsonParser.getIntValue());
//        break;

      case BUILD_SERVER:
        scanBuilder.setHostName(jsonParser.getText());
        break;

      // Skip unneeded fields
      default:
        skipChildren(jsonParser);
        break;
      }
    }
  }

  @Override
  public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vh)
      throws ScanParsingException, IOException {
    LOG.info("SonatypeParserPlugin vulnerabilities parse is starting, sessionId {}", scanData.getSessionId());
    parseJson(scanData, vh, this::parseVulnerabilitiesInternal);
    LOG.info("SonatypeParserPlugin vulnerabilities parse done, sessionId {}", scanData.getSessionId());
  }

  private void parseVulnerabilitiesInternal(final ScanData scanData, final VulnerabilityHandler vh,
      final JsonParser jsonParser) throws ScanParsingException, IOException {
    int debugCounter = 0;
    while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
      final String fieldName = jsonParser.getCurrentName();
      jsonParser.nextToken();
      if (fieldName.equals("findings")) {
        if (jsonParser.currentToken() != JsonToken.START_ARRAY) {
          LOG.error(String.format("Expected array as a value for findings at %s", jsonParser.getTokenLocation()));
          throw new ScanParsingException(
              String.format("Expected array as a value for findings at %s", jsonParser.getTokenLocation()));
        }
        while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
          assertStartObject(jsonParser);
          final String uniqueId = parseVulnerability(scanData, vh, jsonParser);
          if (LOG.isDebugEnabled()) {
            LOG.debug(String.format("Parsed vulnerability %06d/%s in session %s", ++debugCounter, uniqueId,
                scanData.getSessionId()));
          }
        }
      } else {
        skipChildren(jsonParser);
      }
    }
  }

  private String parseVulnerability(final ScanData scanData, final VulnerabilityHandler vh, final JsonParser jsonParser)
      throws IOException {
    final Finding fn = new Finding();
    loadFinding(jsonParser, fn); // Load data from one scan json vulnerability to the Finding onject

    final StaticVulnerabilityBuilder vb = vh.startStaticVulnerability(fn.getUniqueId()); // Start new vulnerability
                                                                                         // building
    populateVulnerability(vb, fn);
    vb.completeVulnerability(); // Complete vulnerability building
    LOG.debug(String.format("Parsed vulnerability ", scanData.getSessionId()));
    return fn.getUniqueId();
  }

  private void loadFinding(final JsonParser jsonParser, Finding fn) throws IOException {
    while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
      VulnAttribute vulnAttr = VulnAttribute.get(jsonParser.getCurrentName());
      jsonParser.nextToken();
      if (vulnAttr == null) {
        skipChildren(jsonParser);
        continue;
      }

      switch (vulnAttr) {
      // Custom mandatory attributes:

      case UNIQUE_ID:
        fn.setUniqueId(jsonParser.getText());
        break;

      // Standard SSC attributes

      case CATEGORY:
        fn.setCategory(jsonParser.getText());
        break;

      case FILE_NAME:
        fn.setFileName(jsonParser.getText());
        break;

      case VULNERABILITY_ABSTRACT:
        fn.setVulnerabilityAbstract(jsonParser.getText());
        break;

//      case LINE_NUMBER:
//        fn.setLineNumber(jsonParser.getIntValue());
//        break;

//      case CONFIDENCE:
//        fn.setConfidence(jsonParser.getFloatValue());
//        break;

//      case IMPACT:
//        fn.setImpact(jsonParser.getFloatValue());
//        break;

      case PRIORITY:
        try {
          fn.setPriority(Finding.Priority.valueOf(jsonParser.getText()));
        } catch (IllegalArgumentException e) {
          fn.setPriority(Finding.Priority.Medium);
        }
        break;

      // Skip unneeded fields:
      default:
        skipChildren(jsonParser);
        break;
      }

      switch (vulnAttr) {
      // Custom attributes

//      case CATEGORY_ID:
//        fn.setCategoryId(jsonParser.getText());
//        break;

      case ARTIFACT:
        fn.setArtifact(jsonParser.getText());
        break;

//      case DESCRIPTION:
//        fn.setDescription(jsonParser.getText());
//        break;

//      case COMMENT:
//        fn.setComment(jsonParser.getText());
//        break;

//      case CUSTOM_STATUS:
//        try {
//          fn.setCustomStatus(Finding.CustomStatus.valueOf(jsonParser.getText()));
//        } catch (IllegalArgumentException e) {
//          fn.setCustomStatus(Finding.CustomStatus.NEW);
//        }
//        break;

      case REPORT_URL:
        fn.setReportUrl(jsonParser.getText());
        break;

      case ISSUE:
        fn.setIssue(jsonParser.getText());
        break;

      case SOURCE:
        fn.setSource(jsonParser.getText());
        break;

      case CVECVSS3:
        fn.setCvecvss3(jsonParser.getText());
        break;

      case CVECVSS2:
        fn.setCvecvss2(jsonParser.getText());
        break;

      case SONATYPECVSS3:
        fn.setSonatypecvss3(jsonParser.getText());
        break;

      case CWECWE:
        fn.setCwecwe(jsonParser.getText());
        break;

      case CWEURL:
        fn.setCweurl(jsonParser.getText());
        break;

      case CVEURL:
        fn.setCveurl(jsonParser.getText());
        break;

      case SONATYPETHREATLEVEL:
        fn.setSonatypeThreatLevel(jsonParser.getText());
        break;

      case GROUP:
        fn.setGroup(jsonParser.getText());
        break;

//                case EFFECTIVE_LICENSE:
//                	fn.setEffectiveLicense(jsonParser.getText());
//                	break;

      case VERSION:
        fn.setVersion(jsonParser.getText());
        break;

//                case CATALOGED:
//                	fn.setCataloged(jsonParser.getText());
//                	break;

//                case MATCHSTATE:
//                	fn.setMatchState(jsonParser.getText());
//                	break;

//                case IDENTIFICATION_SOURCE:
//                	fn.setIdentificationSource(jsonParser.getText());
//                	break;

//      case RECOMMENDED_VERSION:
//        fn.setRecommendedVersion(jsonParser.getText());
//        break;

//                case WEBSITE:
//                    fn.setWebsite(jsonParser.getText());
//                    break;

      // Skip unneeded fields:
      default:
        skipChildren(jsonParser);
        break;
      }
    }
  }

  private void populateVulnerability(final StaticVulnerabilityBuilder vb, final Finding fn) {

    // Set built-in attributes
    vb.setCategory(fn.getCategory()); // REST -> issueName
    vb.setFileName(fn.getFileName()); // REST -> fullFileName or shortFileName
    vb.setVulnerabilityAbstract(fn.getVulnerabilityAbstract()); // REST -> brief
//    vb.setLineNumber(fn.getLineNumber()); // REST -> N/A, UI issue table -> part of Primary Location
//    vb.setConfidence(fn.getConfidence()); // REST -> confidence
//    vb.setImpact(fn.getImpact()); // REST -> impact
    try {
      vb.setPriority(BasicVulnerabilityBuilder.Priority.valueOf(fn.getPriority().name())); // REST -> priority, UI issue
                                                                                           // table -> Criticality
    } catch (IllegalArgumentException e) {
      // Leave priority unset if the value from scan is unknown
    }

    // Set string custom attributes
    populateStringVulnerability(vb, fn);
//        populateStringVulnerabilitySetTwo(vb, fn);

    // set long string custom attributes
    populateLongStringVulnerability(vb, fn);

    // set decimal custom attributes
    populateDecimalVulnerability(vb, fn);
  }

  private void populateStringVulnerability(final StaticVulnerabilityBuilder vb, final Finding fn) {

    if (fn.getUniqueId() != null) {
      vb.setStringCustomAttributeValue(UNIQUE_ID, fn.getUniqueId());
    }
//    if (fn.getCategoryId() != null) {
//      vb.setStringCustomAttributeValue(CATEGORY_ID, fn.getCategoryId());
//    }
    if (fn.getArtifact() != null) {
      vb.setStringCustomAttributeValue(ARTIFACT, fn.getArtifact());
    }
//    if (fn.getCustomStatus() != null) {
//      vb.setStringCustomAttributeValue(CUSTOM_STATUS, fn.getCustomStatus().name());
//    }
    if (fn.getIssue() != null) {
      vb.setStringCustomAttributeValue(ISSUE, fn.getIssue());
    }
    if (fn.getSonatypeThreatLevel() != null) {
      vb.setStringCustomAttributeValue(SONATYPETHREATLEVEL, fn.getSonatypeThreatLevel());
    }
    if (fn.getCweurl() != null) {
      vb.setStringCustomAttributeValue(CWEURL, fn.getCweurl());
    }
    if (fn.getCveurl() != null) {
      vb.setStringCustomAttributeValue(CVEURL, fn.getCveurl());
    }
    if (fn.getGroup() != null) {
      vb.setStringCustomAttributeValue(GROUP, fn.getGroup());
    }
    if (fn.getVersion() != null) {
      vb.setStringCustomAttributeValue(VERSION, fn.getVersion());
    }
//    if (fn.getRecommendedVersion() != null) {
//      vb.setStringCustomAttributeValue(RECOMMENDED_VERSION, fn.getRecommendedVersion());
//    }

  }

//    private void populateStringVulnerabilitySetTwo(final StaticVulnerabilityBuilder vb, final Finding fn) {
//        if (fn.getEffectiveLicense() != null) {
//            vb.setStringCustomAttributeValue( EFFECTIVE_LICENSE, fn.getEffectiveLicense());
//        }
//        if (fn.getCataloged() != null) {
//            vb.setStringCustomAttributeValue( CATALOGED, fn.getCataloged());
//        }
//        if (fn.getMatchState() != null) {
//            vb.setStringCustomAttributeValue( MATCHSTATE, fn.getMatchState());
//        }
//        if (fn.getWebsite() != null) {
//            vb.setStringCustomAttributeValue(WEBSITE, fn.getWebsite());
//        }
//        if (fn.getIdentificationSource() != null) {
//            vb.setStringCustomAttributeValue(IDENTIFICATION_SOURCE, fn.getIdentificationSource());
//        }
//    }

  private void populateLongStringVulnerability(final StaticVulnerabilityBuilder vb, final Finding fn) {
//    if (fn.getComment() != null) {
//      vb.setStringCustomAttributeValue(COMMENT, fn.getComment());
//    }
//    if (fn.getDescription() != null) {
//      vb.setStringCustomAttributeValue(DESCRIPTION, fn.getDescription());
//    }
    if (fn.getReportUrl() != null) {
      vb.setStringCustomAttributeValue(REPORT_URL, fn.getReportUrl());
    }
    if (fn.getSource() != null) {
      vb.setStringCustomAttributeValue(SOURCE, fn.getSource());
    }
  }

  private void populateDecimalVulnerability(final StaticVulnerabilityBuilder vb, final Finding fn) {
    if (fn.getCvecvss3() != null) {
      vb.setDecimalCustomAttributeValue(CVECVSS3, DecimalConverter.convertToBigDecimal(fn.getCvecvss3()));
    }
    if (fn.getCvecvss2() != null) {
      vb.setDecimalCustomAttributeValue(CVECVSS2, DecimalConverter.convertToBigDecimal(fn.getCvecvss2()));
    }
    if (fn.getSonatypecvss3() != null) {
      vb.setDecimalCustomAttributeValue(SONATYPECVSS3, DecimalConverter.convertToBigDecimal(fn.getSonatypecvss3()));
    }
    if (fn.getCwecwe() != null) {
      vb.setDecimalCustomAttributeValue(CWECWE, DecimalConverter.convertToBigDecimal(fn.getCwecwe()));
    }
  }

  private static <T> void parseJson(final ScanData scanData, final T object, final Callback<T> fn)
      throws ScanParsingException, IOException {
    try (final InputStream content = scanData.getInputStream(x -> x.endsWith(".json"));
        final JsonParser jsonParser = JSON_FACTORY.createParser(content)) {
      jsonParser.nextToken();
      assertStartObject(jsonParser);
      fn.apply(scanData, object, jsonParser);
    }
  }

  private static void assertStartObject(final JsonParser jsonParser) throws ScanParsingException {
    if (jsonParser.currentToken() != JsonToken.START_OBJECT) {
      LOG.error(String.format("Expected object start at %s", jsonParser.getTokenLocation()));
      throw new ScanParsingException(String.format("Expected object start at %s", jsonParser.getTokenLocation()));
    }
  }

  private void skipChildren(final JsonParser jsonParser) throws IOException {
    switch (jsonParser.getCurrentToken()) {
    case START_ARRAY:
      // do nothing
    case START_OBJECT:
      jsonParser.skipChildren();
      break;
    default:
      // do nothing
    }
  }

  private interface Callback<T> {
    void apply(final ScanData scanData, final T object, final JsonParser jsonParser)
        throws ScanParsingException, IOException;
  }
}
