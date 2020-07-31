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
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.sonatype.ssc.model.DateDeserializer;
import com.sonatype.ssc.model.DateSerializer;
import com.sonatype.ssc.model.DecimalConverter;
import com.sonatype.ssc.model.Finding;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.sonatype.ssc.plugin.VulnAttribute.*;

public class ScanGenerator {

  private static final DateSerializer DATE_SERIALIZER = new DateSerializer();
  static final DateDeserializer DATE_DESERIALIZER = new DateDeserializer();
  private static final Logger LOG = LoggerFactory.getLogger(ScanGenerator.class);

  private static final String SCAN_TYPE_FIXED = "fixed";
  private static final String SCAN_TYPE_RANDOM = "random";

  private static String scanType;

  private final Random random;
  private final File outputFile;
  private int issueCount;
  private final int categoryCount;

  private ScanGenerator(final Random random, final File outputFile, final int issueCount, final int categoryCount) {
    this.random = random;
    this.outputFile = outputFile;
    this.issueCount = issueCount;
    this.categoryCount = categoryCount;
  }

  private ScanGenerator(final Random random, final File outputFile) {
    this(random, outputFile, 0, 0);
  }

  private static boolean isScanRandom() {
    return SCAN_TYPE_RANDOM.equals(scanType);
  }

  private static boolean isScanFixed() {
    return SCAN_TYPE_FIXED.equals(scanType);
  }

  public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InterruptedException {
    boolean argsOk = false;
    if ((args.length == 5) || (args.length == 2)) {
      scanType = args[0].toLowerCase();
      if (isScanRandom() || isScanFixed()) {
        argsOk = true;
      }
    }
    if (!argsOk) {
      LOG.error(String.format(
          "Usage:\n" + "\tjava -cp <class_path> %s " + SCAN_TYPE_FIXED + " <OUTPUT_SCAN_ZIP_NAME>\n"
              + "\tjava -cp <class_path> %s " + SCAN_TYPE_RANDOM
              + " <OUTPUT_SCAN_ZIP_NAME> <ISSUE_COUNT> <CATEGORY_COUNT>\n",
          ScanGenerator.class.getName(), ScanGenerator.class.getName()));

      System.exit(1);
    }

    ScanGenerator scanGenerator;
    if (isScanFixed()) {
      scanGenerator = new ScanGenerator(SecureRandom.getInstanceStrong(), new File(args[1]));
    } else {
      scanGenerator = new ScanGenerator(SecureRandom.getInstanceStrong(), new File(args[1]), Integer.valueOf(args[2]),
          Integer.valueOf(args[3]));
    }
    scanGenerator.write();
  }

  private void write() throws IOException, InterruptedException {
    if (!outputFile.createNewFile()) {
      LOG.error(String.format("File %s already exists!", outputFile.getPath()));
      System.exit(2);
    }
    try (final OutputStream out = new FileOutputStream(outputFile);
        final ZipOutputStream zipOut = new ZipOutputStream(out)) {
      writeScanInfo("SONATYPE", zipOut);
      if (isScanFixed()) {
        writeScan(zipOut, FixedSampleScan.FIXED_FINDINGS::get, FixedSampleScan.FIXED_FINDINGS.size());
      } else {
        writeScan(zipOut, this::generateFinding, issueCount);
      }
    } catch (final Exception e) {
      try {
        Files.delete(outputFile.toPath());
      } catch (final Exception suppressed) {
        LOG.error("Error while deleting the scan file::" + suppressed.getMessage());
        e.addSuppressed(suppressed);
      }
      throw e;
    }
    LOG.info(String.format("Scan file %s successfully created.", outputFile.getPath()));
  }

  private static void writeScanInfo(final String engineType, final ZipOutputStream zipOut) throws IOException {
    final Properties scanInfoProps = new Properties();
    scanInfoProps.put("engineType", engineType);
    try (final ByteArrayOutputStream byteOut = new ByteArrayOutputStream()) {
      scanInfoProps.store(byteOut, "scan.info");
      zipOut.putNextEntry(new ZipEntry("scan.info"));
      zipOut.write(byteOut.toByteArray());
    }
  }

  private void writeScan(final ZipOutputStream zipOut, Function<Integer, Finding> getFinding, Integer findingCount)
      throws IOException, InterruptedException {

    final long startTime = System.currentTimeMillis();
    final String jsonFileName = isScanFixed() ? "fixed-sample-scan.json" : "random-sample-scan.json";
    zipOut.putNextEntry(new ZipEntry(jsonFileName));
    try (final JsonGenerator jsonGenerator = new JsonFactory().createGenerator(zipOut)) {
      if (isScanFixed()) {
        jsonGenerator.setPrettyPrinter(new DefaultPrettyPrinter());
      }
      jsonGenerator.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
      jsonGenerator.writeStartObject();
      if (isScanFixed()) {
        jsonGenerator.writeStringField(ENGINE_VERSION.attrName(), FixedSampleScan.ENGINE_VERSION);
        jsonGenerator.writeStringField(SCAN_DATE.attrName(), FixedSampleScan.SCAN_DATE);
        jsonGenerator.writeStringField(BUILD_SERVER.attrName(), FixedSampleScan.BUILD_SERVER);
      } else {
        jsonGenerator.writeStringField(ENGINE_VERSION.attrName(), "1.0-SNAPSHOT");
        jsonGenerator.writeStringField(SCAN_DATE.attrName(), DATE_SERIALIZER.convert(new Date()));
        jsonGenerator.writeStringField(BUILD_SERVER.attrName(), Inet4Address.getLocalHost().getHostName());
      }
      jsonGenerator.writeArrayFieldStart("findings");
      int i;
      for (i = 0; i < findingCount; i++) {
        writeFinding(jsonGenerator, getFinding.apply(i));
      }
      jsonGenerator.writeEndArray();
      // NB: this value should be in seconds, but we always want some non-zero value,
      // so we use millis
      if (isScanFixed()) {
        jsonGenerator.writeNumberField(ELAPSED.attrName(), (System.currentTimeMillis() - startTime));
      } else {
        jsonGenerator.writeNumberField(ELAPSED.attrName(), FixedSampleScan.ELAPSED);
      }
      jsonGenerator.writeEndObject();
    }
  }

  private Finding generateFinding(final int i) {
    final String uniqueId = UUID.randomUUID().toString();
    final String id = String.format("%s/%08d", uniqueId, i + 1);
    final int randCat = random.nextInt(categoryCount);

    Finding fn = new Finding();

    // mandatory custom attributes
    fn.setUniqueId(UUID.randomUUID().toString());

    // builtin attributes
    fn.setCategory(String.format("[generated] Random category %d", randCat));
    fn.setFileName(String.format("file-%s.bin", id));
    fn.setVulnerabilityAbstract("Abstract for vulnerability " + id);
    fn.setLineNumber(random.nextInt(Integer.MAX_VALUE));
    fn.setConfidence(random.nextFloat() * 9 + 1); // 1..10
    fn.setImpact(random.nextFloat() + 200f);
    fn.setPriority(Finding.Priority.values()[random.nextInt(Finding.Priority.LENGTH)]);

    // custom attributes
    fn.setCategoryId(String.format("c%d", randCat));
    fn.setArtifact(String.format("artifact-%s.jar", id));
    fn.setDescription("Description for vulnerability " + id + "\nSecurity problem in code...");
    fn.setComment("Comment for vulnerability " + id + "\nMight be a false positive...");
    fn.setCustomStatus(Finding.CustomStatus.values()[random.nextInt(Finding.CustomStatus.LENGTH)]);

    return fn;
  }

  private void writeFinding(final JsonGenerator jsonGenerator, final Finding fn)
      throws IOException, InterruptedException {
    jsonGenerator.writeStartObject();

    // Mandatory custom attributes
    jsonGenerator.writeStringField(UNIQUE_ID.attrName(), fn.getUniqueId());

    // Builtin attributes
    jsonGenerator.writeStringField(CATEGORY.attrName(), fn.getCategory());
    jsonGenerator.writeStringField(FILE_NAME.attrName(), fn.getFileName());
    jsonGenerator.writeStringField(VULNERABILITY_ABSTRACT.attrName(), fn.getVulnerabilityAbstract());
    jsonGenerator.writeNumberField(LINE_NUMBER.attrName(), fn.getLineNumber());
    jsonGenerator.writeNumberField(CONFIDENCE.attrName(), fn.getConfidence());
    jsonGenerator.writeNumberField(IMPACT.attrName(), fn.getImpact());
    jsonGenerator.writeStringField(PRIORITY.attrName(), fn.getPriority().name());

    // Custom attributes
    jsonGenerator.writeStringField(CATEGORY_ID.attrName(), fn.getCategoryId());
    jsonGenerator.writeStringField(CUSTOM_STATUS.attrName(), fn.getCustomStatus().name());
    jsonGenerator.writeStringField(ARTIFACT.attrName(), fn.getArtifact());
    jsonGenerator.writeStringField(DESCRIPTION.attrName(), fn.getDescription());
    jsonGenerator.writeStringField(COMMENT.attrName(), fn.getComment());

    jsonGenerator.writeStringField(REPORT_URL.attrName(), fn.getReportUrl());
    jsonGenerator.writeStringField(GROUP.attrName(), fn.getGroup());
    jsonGenerator.writeStringField(VERSION.attrName(), fn.getVersion());
//        jsonGenerator.writeStringField(EFFECTIVE_LICENSE.attrName(),fn.getEffectiveLicense());
//        jsonGenerator.writeStringField(CATALOGED.attrName(),fn.getCataloged());
//        jsonGenerator.writeStringField(IDENTIFICATION_SOURCE.attrName(),fn.getIdentificationSource());
//        jsonGenerator.writeStringField(WEBSITE.attrName(),fn.getWebsite());
    jsonGenerator.writeStringField(ISSUE.attrName(), fn.getIssue());
    jsonGenerator.writeStringField(SOURCE.attrName(), fn.getSource());
    jsonGenerator.writeStringField(CVECVSS3.attrName(), DecimalConverter.convertToString(fn.getCvecvss3()));
    jsonGenerator.writeStringField(CVECVSS2.attrName(), DecimalConverter.convertToString(fn.getCvecvss2()));
    jsonGenerator.writeStringField(SONATYPECVSS3.attrName(), DecimalConverter.convertToString(fn.getSonatypecvss3()));
    jsonGenerator.writeStringField(CWECWE.attrName(), DecimalConverter.convertToString(fn.getCwecwe()));

    jsonGenerator.writeStringField(CWEURL.attrName(), fn.getCweurl());
    jsonGenerator.writeStringField(CVEURL.attrName(), fn.getCveurl());
    jsonGenerator.writeStringField(SONATYPETHREATLEVEL.attrName(), fn.getSonatypeThreatLevel());

    jsonGenerator.writeEndObject();
  }
}