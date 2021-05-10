package com.sonatype.ssc.plugin.util;

import static com.sonatype.ssc.plugin.VulnAttribute.*;

import static org.junit.Assert.assertNotNull;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.nio.file.Files;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.sonatype.ssc.model.Finding;

public class TestSonatypeParser {

  private static final DateSerializer DATE_SERIALIZER = new DateSerializer();
  private static final Logger LOG = LoggerFactory.getLogger(TestSonatypeParser.class);

  private static final String SCAN_TYPE_FIXED = "fixed";

  private String scanType;

  private Random randomTest;
  private int issueCount;
  private int categoryCount;

  private boolean isScanFix() {
    return SCAN_TYPE_FIXED.equals(scanType);
  }

  @Test
  public void testWrite() throws IOException, InterruptedException {

    File propertyFile = new File("parser.properties");
    Properties properties = new Properties();
    properties.load(new FileInputStream(propertyFile));

    File outputFile = null;

    if (properties.getProperty("scanfile.location") != null) {
      outputFile = new File(properties.getProperty("scanfile.location"));
    }
    if (properties.getProperty("scanfile.scantype") != null) {
      scanType = properties.getProperty("scanfile.scantype");
    }

    if (outputFile != null) {
      try (final OutputStream out = new FileOutputStream(outputFile);
          final ZipOutputStream zipOut = new ZipOutputStream(out)) {
        assertNotNull("zipfile is null", zipOut);
        writeInfo("SONATYPE", zipOut);
        if (isScanFix()) {
          writeTestScan(zipOut, FixedSampleScan.FIXED_FINDINGS::get, FixedSampleScan.FIXED_FINDINGS.size());
        } else {
          writeTestScan(zipOut, this::generateTestFinding, issueCount);
        }
      } catch (final Exception e) {
        LOG.error("Error while generating test scan file::" + e.getMessage());
        try {
          if (outputFile != null)
            Files.delete(outputFile.toPath());
        } catch (final Exception suppressed) {
          LOG.error("Error while deleting the scan file::" + suppressed.getMessage());
          e.addSuppressed(suppressed);
        }
        throw e;
      }
      LOG.info(String.format("Scan file %s successfully created.", outputFile.getPath()));
    }

  }

  private static void writeInfo(final String engineType, final ZipOutputStream zipOut) throws IOException {
    final Properties scanInfoProps = new Properties();
    scanInfoProps.put("engineType", engineType);
    try (final ByteArrayOutputStream byteOut = new ByteArrayOutputStream()) {
      scanInfoProps.store(byteOut, "scan.info");
      zipOut.putNextEntry(new ZipEntry("scan.info"));
      zipOut.write(byteOut.toByteArray());
    }
  }

  private void writeTestScan(final ZipOutputStream zipOut, Function<Integer, Finding> getFinding, Integer findingCount)
      throws IOException, InterruptedException {

    //final long testStartTime = System.currentTimeMillis();
    final String testJsonFileName = isScanFix() ? "fixed-sample-scan.json" : "random-sample-scan.json";
    zipOut.putNextEntry(new ZipEntry(testJsonFileName));
    try (final JsonGenerator testJsonGenerator = new JsonFactory().createGenerator(zipOut)) {
      if (isScanFix()) {
        testJsonGenerator.setPrettyPrinter(new DefaultPrettyPrinter());
      }
      testJsonGenerator.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
      testJsonGenerator.writeStartObject();
      if (isScanFix()) {
        testJsonGenerator.writeStringField(ENGINE_VERSION.attrName(), FixedSampleScan.ENGINE_VERSION);
        testJsonGenerator.writeStringField(SCAN_DATE.attrName(), FixedSampleScan.SCAN_DATE);
        testJsonGenerator.writeStringField(BUILD_SERVER.attrName(), FixedSampleScan.BUILD_SERVER);
      } else {
        testJsonGenerator.writeStringField(ENGINE_VERSION.attrName(), "1.0-SNAPSHOT");
        testJsonGenerator.writeStringField(SCAN_DATE.attrName(), DATE_SERIALIZER.convert(new Date()));
        testJsonGenerator.writeStringField(BUILD_SERVER.attrName(), Inet4Address.getLocalHost().getHostName());
      }
      testJsonGenerator.writeArrayFieldStart("findings");
      int i;
      for (i = 0; i < findingCount; i++) {
        writeFinding(testJsonGenerator, getFinding.apply(i));
      }
      testJsonGenerator.writeEndArray();
      // NB: this value should be in seconds, but we always want some non-zero value,
      // so we use millis
      /*if (isScanFix()) {
        testJsonGenerator.writeNumberField(ELAPSED.attrName(), (System.currentTimeMillis() - testStartTime));
      } else {
        testJsonGenerator.writeNumberField(ELAPSED.attrName(), FixedSampleScan.ELAPSED);
      }*/
      testJsonGenerator.writeEndObject();
    }
  }

  private Finding generateTestFinding(final int i) {
    final String uniqueTestId = UUID.randomUUID().toString();
    final String testId = String.format("%s/%08d", uniqueTestId, i + 1);
    final int randTestCat = randomTest.nextInt(categoryCount);

    Finding fn = new Finding();

    // mandatory custom attributes
    fn.setUniqueId(UUID.randomUUID().toString());

    // builtin attributes
    fn.setCategory(String.format("[generated] Random category %d", randTestCat));
    fn.setFileName(String.format("file-%s.bin", testId));
    fn.setVulnerabilityAbstract("Abstract for vulnerability " + testId);
//    fn.setLineNumber(randomTest.nextInt(Integer.MAX_VALUE));
//    fn.setConfidence(randomTest.nextFloat() * 9 + 1); // 1..10
//    fn.setImpact(randomTest.nextFloat() + 200f);

    // custom attributes
//    fn.setCategoryId(String.format("c%d", randTestCat));
    fn.setArtifact(String.format("artifact-%s.jar", testId));
//    fn.setDescription("Description for vulnerability " + testId + "\nSecurity problem in code...");
//    fn.setComment("Comment for vulnerability " + testId + "\nMight be a false positive...");

    return fn;
  }

  private void writeFinding(final JsonGenerator jsonGenerator, final Finding fn)
      throws IOException, InterruptedException {
    jsonGenerator.writeStartObject();

    // Mandatory custom attributes
    jsonGenerator.writeStringField(UNIQUE_ID.attrName(), fn.getUniqueId());
    assertNotNull("Unique Id field is null", fn.getUniqueId());

    // Builtin attributes
    jsonGenerator.writeStringField(CATEGORY.attrName(), fn.getCategory());
    assertNotNull("Category field  is  null", fn.getCategory());
    jsonGenerator.writeStringField(FILE_NAME.attrName(), fn.getFileName());
    assertNotNull("Filename field is  null", fn.getFileName());
    jsonGenerator.writeStringField(VULNERABILITY_ABSTRACT.attrName(), fn.getVulnerabilityAbstract());
    assertNotNull("VulnerabilityAbstract field is  null", fn.getVulnerabilityAbstract());
//    jsonGenerator.writeNumberField(LINE_NUMBER.attrName(), fn.getLineNumber());
//    assertNotNull("LineNumber field is  null", fn.getLineNumber());
//    jsonGenerator.writeNumberField(CONFIDENCE.attrName(), fn.getConfidence());
//    assertNotNull("Confidence field is  null", fn.getConfidence());
//    jsonGenerator.writeNumberField(IMPACT.attrName(), fn.getImpact());
//    assertNotNull("Impact field is  null", fn.getImpact());
    jsonGenerator.writeStringField(PRIORITY.attrName(), fn.getPriority().name());
    assertNotNull("Priority name field is  null", fn.getPriority().name());

    // Custom attributes
//    jsonGenerator.writeStringField(CATEGORY_ID.attrName(), fn.getCategoryId());
//    assertNotNull("Category Id field is  null", fn.getCategoryId());
//    jsonGenerator.writeStringField(CUSTOM_STATUS.attrName(), fn.getCustomStatus().name());
//    assertNotNull("Custom Status field is  null", fn.getCustomStatus().name());
    jsonGenerator.writeStringField(ARTIFACT.attrName(), fn.getArtifact());
    assertNotNull("Artifact field is  null", fn.getArtifact());
//    jsonGenerator.writeStringField(DESCRIPTION.attrName(), fn.getDescription());
//    assertNotNull("Description field is  null", fn.getDescription());
//    jsonGenerator.writeStringField(COMMENT.attrName(), fn.getComment());
//    assertNotNull("Comment field is  null", fn.getComment());

    jsonGenerator.writeStringField(REPORT_URL.attrName(), fn.getReportUrl());
    assertNotNull("Report url field is  null", fn.getReportUrl());
    jsonGenerator.writeStringField(GROUP.attrName(), fn.getGroup());
    assertNotNull("Group  field is  null", fn.getGroup());
    jsonGenerator.writeStringField(VERSION.attrName(), fn.getVersion());
    assertNotNull("Version field is  null", fn.getVersion());
//    jsonGenerator.writeStringField(EFFECTIVE_LICENSE.attrName(), fn.getEffectiveLicense());
//    assertNotNull("Effective license field is  null", fn.getEffectiveLicense());
//    jsonGenerator.writeStringField(CATALOGED.attrName(), fn.getCataloged());
//    assertNotNull("Cataloged field is  null", fn.getCataloged());
//    jsonGenerator.writeStringField(IDENTIFICATION_SOURCE.attrName(), fn.getIdentificationSource());
//    assertNotNull("Identification source field  is  null", fn.getIdentificationSource());
//    jsonGenerator.writeStringField(WEBSITE.attrName(), fn.getWebsite());
//    assertNotNull("Website field is  null", fn.getWebsite());
    jsonGenerator.writeStringField(ISSUE.attrName(), fn.getIssue());
    assertNotNull("Issue field is  null", fn.getIssue());
    jsonGenerator.writeStringField(SOURCE.attrName(), fn.getSource());
    assertNotNull("Source field is  null", fn.getSource());
    jsonGenerator.writeStringField(CVECVSS3.attrName(), fn.getCvecvss3());
    jsonGenerator.writeStringField(CVECVSS2.attrName(), fn.getCvecvss2());
    assertNotNull("Cvecvss2 field is  null", fn.getCvecvss2());
    jsonGenerator.writeStringField(SONATYPECVSS3.attrName(), fn.getSonatypecvss3());
    jsonGenerator.writeStringField(CWECWE.attrName(), fn.getCwecwe());

    jsonGenerator.writeStringField(CWEURL.attrName(), fn.getCweurl());
    assertNotNull("Cweurl field is  null", fn.getCweurl());
    jsonGenerator.writeStringField(CVEURL.attrName(), fn.getCveurl());
    jsonGenerator.writeStringField(SONATYPETHREATLEVEL.attrName(), fn.getSonatypeThreatLevel());

    jsonGenerator.writeEndObject();
  }
}
