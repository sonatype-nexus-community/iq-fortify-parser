package com.sonatype.ssc.plugin;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import com.sonatype.ssc.model.Finding;

import static com.sonatype.ssc.plugin.ScanGenerator.GenPriority;
import static com.sonatype.ssc.plugin.ScanGenerator.CustomStatus;
import static com.sonatype.ssc.plugin.ScanGenerator.DATE_DESERIALIZER;

class FixedSampleScan {
	
	  private FixedSampleScan() {
		    throw new IllegalStateException("FixedSampleScan class");
		  }

	
    static final List<Finding> FIXED_FINDINGS = generateFixedFindings();

    static final String ENGINE_VERSION = "1.0-SNAPSHOT";
    static final String SCAN_DATE = "2017-04-18T23:31:42.136Z";
    static final String BUILD_SERVER = "server01";
    static final int ELAPSED = 860;
    private static final String CONT_CAT = "Cross-site Scripting";
    private static final String CONT_VUL = "RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution";
    private static final String CONT_SRC = "National Vulnerabilty Database";
    private static final String CONT_DESC = "Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007.[1] Their effect may range from a petty nuisance to a significant security risk, depending on the sensitivity of the data handled by the vulnerable site and the nature of any security mitigation implemented by the site's owner.";
    private static final String CONT_BUILD = "300.3837014436722";
    private static final String CONT_CWEURL = "https://cwe.mitre.org/data/definitions/502.html";
    private static final String CONT_VER = "1.1.11";
    private static final String CONT_GRP = "ch.qos.logback";
    private static final String CONT_ID_SRC = "Sonatype";
    private static final String CONT_CTL = "2 years ago";
    private static final String CONT_MATCH = "Exact";
    private static final String LAST_DATE ="2017-04-16T21:31:42.092Z";
    private static final String BUILD_DATE = "2017-04-17T22:31:42.092Z";
    private static final String TEXT_BASE = "Example of a text encoded in the original scan to Base64. \n";
    private static final String RPT_URL = "http://iq-server.company.com/assets/index.html";
    private static final String WEB_URL =  "http://tomcat.apache.org";
    private static final String ARTIFACT ="artifact-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.jar";
    private static final String COMMENT = "fixed in build 300.845200451";
    private static final String TEST = "sample";
    
    private static List<Finding> generateFixedFindings() {
        List<Finding> findingList = new ArrayList<>();
        
        for (int i=0;i<10;i++){
	        Finding fn = new Finding();
	        // Mandatory custom attributes:
	        fn.setUniqueId("fda2eaa2-7643-4fc5-809e-3eb6957e1945");
	        // Builtin attributes:
	        fn.setCategory(CONT_CAT);
	        fn.setFileName("file-fda2eaa2-7643-4fc5-809e-3eb6957e1945/00000001.bin");
	        fn.setVulnerabilityAbstract(CONT_VUL);
	        fn.setLineNumber(103);
	        fn.setConfidence(4.968653f);
	        fn.setImpact(200.690f);
	        fn.setPriority(GenPriority.Critical);
	        // Custom attributes:
	        fn.setSource(CONT_SRC);
	        fn.setCategoryId("a101");
	        fn.setArtifact("logback-classic");
	        fn.setDescription(CONT_DESC);
	        fn.setComment("This should be fixed");
	        fn.setBuildNumber(CONT_BUILD);
	        fn.setIssue("CVE-2017-5929");
	        fn.setCustomStatus(CustomStatus.OPEN);
	        fn.setCwecwe(new BigDecimal("502"));
	        fn.setCvecvss2(new BigDecimal("7.5"));
	        fn.setCweurl(CONT_CWEURL);
	        fn.setVersion(CONT_VER);
	        fn.setGroup(CONT_GRP);
	        fn.setEffectiveLicense("MIT");
	        fn.setIdentificationSource(CONT_ID_SRC);
	        fn.setCataloged(CONT_CTL);
	        fn.setTest(TEST);
	        fn.setArtifact(ARTIFACT);
	        fn.setComment(COMMENT);
	        fn.setMatchState(CONT_MATCH);
	        fn.setLastChangeDate(DATE_DESERIALIZER.convert(LAST_DATE));
	        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert(BUILD_DATE));
	        fn.setTextBase64(TEXT_BASE + LONG_TEXT);
	        fn.setReportUrl(RPT_URL);
	        fn.setWebsite(WEB_URL);
	        findingList.add(fn);
        }

        return findingList;
    }

private static final String LONG_TEXT = "From Wikipedia: \n"+
    "\n"+
    "Computer security, also known as cyber security or IT security, is the protection of computer systems from the theft or damage to their hardware, software or information, as well as from disruption or misdirection of the services they provide. \n"+
    "\n"+
    "Cyber security includes controlling physical access to the hardware, as well as protecting against harm that may come via network access, data and code injection. Also, due to malpractice by operators, whether intentional, accidental, IT security is susceptible to being tricked into deviating from secure procedures through various methods.\n";

}
