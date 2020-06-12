package com.thirdparty;

import static com.thirdparty.VulnAttribute.ARTIFACT;
import static com.thirdparty.VulnAttribute.ARTIFACT_BUILD_DATE;
import static com.thirdparty.VulnAttribute.BUILD_NUMBER;
import static com.thirdparty.VulnAttribute.BUILD_SERVER;
//import static com.thirdparty.VulnAttribute.CATALOGED;
import static com.thirdparty.VulnAttribute.CATEGORY;
import static com.thirdparty.VulnAttribute.CATEGORY_ID;
import static com.thirdparty.VulnAttribute.COMMENT;
import static com.thirdparty.VulnAttribute.CONFIDENCE;
import static com.thirdparty.VulnAttribute.CUSTOM_STATUS;
import static com.thirdparty.VulnAttribute.CVECVSS2;
import static com.thirdparty.VulnAttribute.CVECVSS3;
import static com.thirdparty.VulnAttribute.CVEURL;
import static com.thirdparty.VulnAttribute.CWECWE;
import static com.thirdparty.VulnAttribute.CWEURL;
import static com.thirdparty.VulnAttribute.DESCRIPTION;
//import static com.thirdparty.VulnAttribute.EFFECTIVE_LICENSE;
import static com.thirdparty.VulnAttribute.ELAPSED;
import static com.thirdparty.VulnAttribute.ENGINE_VERSION;
import static com.thirdparty.VulnAttribute.FILE_NAME;
import static com.thirdparty.VulnAttribute.GROUP;
//import static com.thirdparty.VulnAttribute.IDENTIFICATION_SOURCE;
import static com.thirdparty.VulnAttribute.IMPACT;
import static com.thirdparty.VulnAttribute.ISSUE;
import static com.thirdparty.VulnAttribute.LAST_CHANGE_DATE;
import static com.thirdparty.VulnAttribute.LINE_NUMBER;
import static com.thirdparty.VulnAttribute.PRIORITY;
import static com.thirdparty.VulnAttribute.REPORT_URL;
import static com.thirdparty.VulnAttribute.SCAN_DATE;
import static com.thirdparty.VulnAttribute.SONATYPECVSS3;
import static com.thirdparty.VulnAttribute.SONATYPETHREATLEVEL;
import static com.thirdparty.VulnAttribute.SOURCE;
import static com.thirdparty.VulnAttribute.TEXT_BASE64;
import static com.thirdparty.VulnAttribute.UNIQUE_ID;
import static com.thirdparty.VulnAttribute.VERSION;
import static com.thirdparty.VulnAttribute.VULNERABILITY_ABSTRACT;
//import static com.thirdparty.VulnAttribute.WEBSITE;
import static org.junit.Assert.assertNotNull;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.Inet4Address;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;

import com.thirdparty.scan.DateDeserializer;
import com.thirdparty.scan.DateSerializer;
import com.thirdparty.scan.DemicalConverter;
import com.thirdparty.scan.Finding;

public class TestSonatypeParser {

	private static final DateSerializer DATE_SERIALIZER = new DateSerializer();
	static final DateDeserializer DATE_DESERIALIZER = new DateDeserializer();
	private static final Charset charset = StandardCharsets.US_ASCII;
	private static final Logger LOG = LoggerFactory.getLogger(ScanGenerator.class);

	// GenPriority should exactly copy values from
	// com.fortify.plugin.api.BasicVulnerabilityBuilder.Priority
	// We don't use the original Priority here because we don't want generator to be
	// dependent on the plugin-api
	public enum GenPriority {
		CRITICAL, HIGH, MEDIUM, LOW;
		static final int LENGTH = values().length;
	}

	public enum CustomStatus {
		NEW, OPEN, REMEDIATED;
		static final int LENGTH = values().length;
	}

	private static final String SCAN_TYPE_FIXED = "fixed";

	private String scanType;

	private Random randomTest;
	private int issueCount;
	private int categoryCount;
	private int longTextSize;
	private Instant now;

	private boolean isScanFix() {
		return SCAN_TYPE_FIXED.equals(scanType);
	}

	@Test
	public void testWrite() throws IOException, InterruptedException {

		File propertyFile = new File("parser.properties");
		FileInputStream propertyFileStream = new FileInputStream(propertyFile);
		Properties properties = new Properties();
		properties.load(propertyFileStream);

		File outputFile = null;

		if (properties.getProperty("scanfile.location") != null) {

			outputFile = new File(properties.getProperty("scanfile.location"));

		}
		if (properties.getProperty("scanfile.scantype") != null) {

			scanType = properties.getProperty("scanfile.scantype");

		}
		
		if(outputFile != null && outputFile.exists()){
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
				LOG.error("Error while scanning the scan file::" + e.getMessage());
				try {
					if(outputFile != null)
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

		final long testStartTime = System.currentTimeMillis();
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
			if (isScanFix()) {
				testJsonGenerator.writeNumberField(ELAPSED.attrName(), (System.currentTimeMillis() - testStartTime));
			} else {
				testJsonGenerator.writeNumberField(ELAPSED.attrName(), FixedSampleScan.ELAPSED);
			}
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
		fn.setLineNumber(randomTest.nextInt(Integer.MAX_VALUE));
		fn.setConfidence(randomTest.nextFloat() * 9 + 1); // 1..10
		fn.setImpact(randomTest.nextFloat() + 200f);

		// custom attributes
		fn.setCategoryId(String.format("c%d", randTestCat));
		fn.setArtifact(String.format("artifact-%s.jar", testId));
		fn.setDescription("Description for vulnerability " + testId + "\nSecurity problem in code...");
		fn.setComment("Comment for vulnerability " + testId + "\nMight be a false positive...");
		fn.setBuildNumber(String.valueOf(randomTest.nextFloat() + 300f));
		fn.setLastChangeDate(Date.from(now.minus(2, ChronoUnit.DAYS).minus(2, ChronoUnit.HOURS)));
		fn.setArtifactBuildDate(Date.from(now.minus(1, ChronoUnit.DAYS).minus(1, ChronoUnit.HOURS)));
		fn.setTextBase64("Very long text for " + testId + ": \n");

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
		jsonGenerator.writeNumberField(LINE_NUMBER.attrName(), fn.getLineNumber());
		assertNotNull("LineNumber field is  null", fn.getLineNumber());
		jsonGenerator.writeNumberField(CONFIDENCE.attrName(), fn.getConfidence());
		assertNotNull("Confidence field is  null", fn.getConfidence());
		jsonGenerator.writeNumberField(IMPACT.attrName(), fn.getImpact());
		assertNotNull("Impact field is  null", fn.getImpact());
		jsonGenerator.writeStringField(PRIORITY.attrName(), fn.getPriority().name());
		assertNotNull("Priority name field is  null", fn.getPriority().name());

		// Custom attributes
		jsonGenerator.writeStringField(CATEGORY_ID.attrName(), fn.getCategoryId());
		assertNotNull("Category Id field is  null", fn.getCategoryId());
		jsonGenerator.writeStringField(CUSTOM_STATUS.attrName(), fn.getCustomStatus().name());
		assertNotNull("Custom Status field is  null", fn.getCustomStatus().name());
		jsonGenerator.writeStringField(ARTIFACT.attrName(), fn.getArtifact());
		assertNotNull("Artifact field is  null", fn.getArtifact());
		jsonGenerator.writeStringField(DESCRIPTION.attrName(), fn.getDescription());
		assertNotNull("Description field is  null", fn.getDescription());
		jsonGenerator.writeStringField(COMMENT.attrName(), fn.getComment());
		assertNotNull("Comment field is  null", fn.getComment());
		jsonGenerator.writeStringField(BUILD_NUMBER.attrName(), fn.getBuildNumber());
		assertNotNull("Build number field is  null", fn.getBuildNumber());

		jsonGenerator.writeStringField(REPORT_URL.attrName(), fn.getReportUrl());
		assertNotNull("Report url field is  null", fn.getReportUrl());
		jsonGenerator.writeStringField(GROUP.attrName(), fn.getGroup());
		assertNotNull("Group  field is  null", fn.getGroup());
		jsonGenerator.writeStringField(VERSION.attrName(), fn.getVersion());
		assertNotNull("Version field is  null", fn.getVersion());
//		jsonGenerator.writeStringField(EFFECTIVE_LICENSE.attrName(), fn.getEffectiveLicense());
//		assertNotNull("Effective license field is  null", fn.getEffectiveLicense());
//		jsonGenerator.writeStringField(CATALOGED.attrName(), fn.getCataloged());
//		assertNotNull("Cataloged field is  null", fn.getCataloged());
//		jsonGenerator.writeStringField(IDENTIFICATION_SOURCE.attrName(), fn.getIdentificationSource());
//		assertNotNull("Identification source field  is  null", fn.getIdentificationSource());
//		jsonGenerator.writeStringField(WEBSITE.attrName(), fn.getWebsite());
//		assertNotNull("Website field is  null", fn.getWebsite());
		jsonGenerator.writeStringField(ISSUE.attrName(), fn.getIssue());
		assertNotNull("Issue field is  null", fn.getIssue());
		jsonGenerator.writeStringField(SOURCE.attrName(), fn.getSource());
		assertNotNull("Source field is  null", fn.getSource());
		jsonGenerator.writeStringField(CVECVSS3.attrName(), DemicalConverter.convertToString(fn.getCvecvss3()));
		jsonGenerator.writeStringField(CVECVSS2.attrName(), DemicalConverter.convertToString(fn.getCvecvss2()));
		assertNotNull("Cvecvss2 field is  null", fn.getCvecvss2());
		jsonGenerator.writeStringField(SONATYPECVSS3.attrName(),
				DemicalConverter.convertToString(fn.getSonatypecvss3()));
		jsonGenerator.writeStringField(CWECWE.attrName(), DemicalConverter.convertToString(fn.getCwecwe()));

		jsonGenerator.writeStringField(CWEURL.attrName(), fn.getCweurl());
		assertNotNull("Cweurl field is  null", fn.getCweurl());
		jsonGenerator.writeStringField(CVEURL.attrName(), fn.getCveurl());
		jsonGenerator.writeStringField(SONATYPETHREATLEVEL.attrName(), fn.getSonatypeThreatLevel());
		jsonGenerator.writeStringField(LAST_CHANGE_DATE.attrName(), DATE_SERIALIZER.convert(fn.getLastChangeDate()));
		assertNotNull("Last change date field is  null", fn.getLastChangeDate());
		jsonGenerator.writeStringField(ARTIFACT_BUILD_DATE.attrName(),

				DATE_SERIALIZER.convert(fn.getArtifactBuildDate()));
		assertNotNull("Artifact Build Date field is  null", fn.getArtifactBuildDate());
		jsonGenerator.writeFieldName(TEXT_BASE64.attrName());

		writeLoremIpsum(fn.getTextBase64(), jsonGenerator);

		jsonGenerator.writeEndObject();
	}

	private void writeLoremIpsum(final String name, final JsonGenerator jsonGenerator)
			throws InterruptedException, IOException {
		final int size = longTextSize + name.length();
		try (final InputStream in = getTestByte(name, size)) {
			jsonGenerator.writeBinary(in, size);
		}
	}

	private static InputStream getTestByte(final String name, final int size) {
		final CountDownLatch testLatch = new CountDownLatch(1);
		try (final PipedInputStream testIn = new PipedInputStream();) {
			final Thread t1 = new Thread(() -> pipeStreamProd(name, testIn, testLatch, size));
			t1.setDaemon(true);
			t1.start();
			if (testLatch.await(10, TimeUnit.SECONDS)) {
				return testIn;
			} else {
				t1.interrupt();
				LOG.error("Timeout while waiting for latch for " + name);
				throw new TimeoutException("Timeout while waiting for latch for " + name);
			}
		} catch (final Exception e) {
			LOG.error("Error while getting::" + e.getMessage());
			return null;
		}
	}

	private static void pipeStreamProd(final String name, final PipedInputStream in, final CountDownLatch latch,
			final int size) {
		try (final PipedOutputStream out = new PipedOutputStream(in)) {
			latch.countDown();
			int written = min(name.length(), size);
			out.write(name.getBytes(charset), 0, written);
			final int loremIpsumLen = testByte.length;
			while (written < size) {
				final int len = min(loremIpsumLen, size - written);
				out.write(testByte, 0, len);
				written += len;
			}
		} catch (final IOException e) {
			LOG.error("Error while writing::" + e.getMessage());
		}
	}

	private static int min(final int i, final int j) {
		return i < j ? i : j;
	}

	private static byte[] testByte = ("Lorem ipsum dolor sit amet, eam ridens cetero iuvaret id. Ius eros fabulas ei. Te vis unum intellegam, cu sed ullum eruditi, et est lorem volumus. Te altera malorum quaestio mei, sea ea veniam disputando.\n"
			+ "\n"
			+ "Illud labitur definitionem ut sit, veri illum qui ut. Ludus patrioque voluptaria pri ad. Magna mundi voluptatum his ea. His paulo possim ea, et vide omittam philosophia sit. Eu lucilius legendos incorrupte eos, eu falli molestie argumentum cum.\n"
			+ "\n"
			+ "Melius torquatos ea his. Movet dolorem cu eam. Nisl offendit repudiare ne est. No veri appareat petentium eum.\n"
			+ "\n"
			+ "Duo in omnium accumsan legendos. Pro id probo oportere salutatus, sonet omnium epicurei eu pri. Indoctum disputando ei sea, an viris legere delicatissimi vix, ne dico melius admodum eam. Pro nostro inimicus liberavisse an. Id pro nostrum theophrastus, his et liber iusto docendi, purto convenire tincidunt pri an.\n"
			+ "\n"
			+ "Ex ubique accusamus est. Te sumo persecuti mei. Ne veniam mollis mei, natum perfecto definitionem at has. Liber honestatis ad cum, porro expetendis conclusionemque per eu. Suscipit dissentiet per an, ad usu sumo homero debitis. At eam quando placerat, nonumy forensibus scripserit at pro.\n"
			+ "\n"
			+ "Vero quodsi no usu, usu nisl erat iracundia in. Sed te habeo viris graeco. Persius admodum sententiae no eam, ut dicunt erroribus sit. Dolorum appetere legendos et qui. Vim ei feugait perfecto sadipscing.\n"
			+ "\n"
			+ "Nam audire detracto et, epicurei suscipiantur at his, vis id veri dolor. Pro id insolens singulis, accumsan singulis eam at, qui cu diam ceteros singulis. Atqui graecis fastidii cu mei. Invidunt singulis ex eam, et detracto hendrerit sadipscing quo. Est ne graeci vidisse placerat, wisi appareat erroribus ius an. Ea vim dicam aperiri. Ex elit aliquid est, nostro intellegam mel te.\n"
			+ "\n"
			+ "Eu per consul semper vituperatoribus, odio dicat audiam eam ea. Qui ei iisque nonumes repudiare, fugit quidam eu sit. An eam debet concludaturque, in nostro meliore splendide quo, ei est eros accumsan scribentur. Ei idque dolore honestatis sea. Tollit convenire salutatus ex mea, quem tantas epicurei in usu.\n"
			+ "\n"
			+ "Nam at cibo nominati, ne meis harum per, eu cum brute saepe veniam. Quo fabulas insolens cu, vix ne animal detraxit. Adhuc paulo similique ut eam, cu sit persius phaedrum. Cu eruditi periculis salutatus est, dicam veniam verterem ius at.\n"
			+ "\n"
			+ "Everti vivendum splendide ad qui, ad quod nominavi comprehensam quo, mollis scripta eu eum. Te pro dicta volumus, his affert ornatus dissentias id. Mea no quot referrentur, an his eius eripuit noluisse. His eu legere eruditi.")
					.getBytes(charset);
}
