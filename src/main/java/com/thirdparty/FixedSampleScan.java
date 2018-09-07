package com.thirdparty;

/**
 * (c) Copyright [2017] Micro Focus or one of its affiliates.
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

import com.thirdparty.scan.Finding;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

import static com.thirdparty.ScanGenerator.GenPriority;
import static com.thirdparty.ScanGenerator.CustomStatus;
import static com.thirdparty.ScanGenerator.DATE_DESERIALIZER;

class FixedSampleScan {

    static final List<Finding> FIXED_FINDINGS = generateFixedFindings();

    static final String ENGINE_VERSION = "1.0-SNAPSHOT";
    static final String SCAN_DATE = "2017-04-18T23:31:42.136Z";
    static final String BUILD_SERVER = "server01";
    static final int ELAPSED = 860;

    private static List<Finding> generateFixedFindings() {
        List<Finding> findingList = new ArrayList<>();

        Finding fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("fda2eaa2-7643-4fc5-809e-3eb6957e1945");
        // Builtin attributes:
        fn.setCategory("Cross-site Scripting");
        fn.setFileName("file-fda2eaa2-7643-4fc5-809e-3eb6957e1945/00000001.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(103);
        fn.setConfidence(4.968653f);
        fn.setImpact(200.690f);
        fn.setPriority(GenPriority.Critical);
        // Custom attributes:
        fn.setCategoryId("a101");
        fn.setArtifact("artifact-fda2eaa2-7643-4fc5-809e-3eb6957e1945/00000001.jar");
        fn.setDescription("Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007.[1] Their effect may range from a petty nuisance to a significant security risk, depending on the sensitivity of the data handled by the vulnerable site and the nature of any security mitigation implemented by the site's owner.");
        fn.setComment("This should be fixed");
        fn.setBuildNumber("300.3837014436722");
        fn.setIssue("CVE-2017-5929");
        fn.setCustomStatus(CustomStatus.OPEN);
        fn.setCwecwe(new BigDecimal("502"));
        fn.setName("jquery");
        fn.setVersion("1.1.11");
        fn.setCataloged("2 years ago");
        fn.setTest("sample");
        fn.setMatchState("Exact");
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("fda2eaa2-7643-4fc5-809e-3eb6957e1999");
        // Builtin attributes:
        fn.setCategory("Cross-site Scripting");
        fn.setFileName("file-fda2eaa2-7643-4fc5-809e-3eb6957e1999/00000021.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(146);
        fn.setConfidence(4.968653f);
        fn.setImpact(200.690f);
        fn.setPriority(GenPriority.Critical);
        // Custom attributes:
        fn.setCategoryId("a101");
        fn.setArtifact("artifact-fda2eaa2-7643-4fc5-809e-3eb6957e1999/00000001.jar");
        fn.setDescription("Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007.[1] Their effect may range from a petty nuisance to a significant security risk, depending on the sensitivity of the data handled by the vulnerable site and the nature of any security mitigation implemented by the site's owner.");
        fn.setComment("This should be fixed");
        fn.setBuildNumber("300.3837014436722");
        fn.setIssue("CVE-2017-5929");
        fn.setCustomStatus(CustomStatus.OPEN);
        fn.setCwecwe(new BigDecimal("502"));
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
        fn.setName("jquery");
        fn.setVersion("1.1.11");
        fn.setGroup("ch.qos.logback");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
        fn.setTest("sample");
        
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("fda2eaa2-7643-4fc5-809e-3eb6957e1946");
        // Builtin attributes:
        fn.setCategory("Cross-site Scripting");
        fn.setFileName("file-fda2eaa2-7643-4fc5-809e-3eb6957e1946/00000011.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(489);
        fn.setConfidence(4.968653f);
        fn.setImpact(200.690f);
        fn.setPriority(GenPriority.Critical);
        // Custom attributes:
        fn.setCategoryId("a101");
        fn.setArtifact("artifact-fda2eaa2-7643-4fc5-809e-3eb6957e1946/00000001.jar");
        fn.setDescription("Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007.[1] Their effect may range from a petty nuisance to a significant security risk, depending on the sensitivity of the data handled by the vulnerable site and the nature of any security mitigation implemented by the site's owner.");
        fn.setComment("fixed in build 303.0001");
        fn.setBuildNumber("300.3837014436722");
        fn.setIssue("CVE-2017-5929");
        fn.setSource("National Vulnerabilty Database");
        fn.setCvecvss3(new BigDecimal("9.8"));
       // fn.setCvecvss2("7.5");
       // fn.setCvecvss2("7.5");
        fn.setSonatypecvss3(new BigDecimal("9.8"));
        fn.setCwecwe(new BigDecimal("502"));
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
        fn.setName("jquery");
        fn.setGroup("ch.qos.logback");
        fn.setVersion("1.1.11");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
        fn.setTest("sample");
      /*  fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        
        fn.setCustomStatus(CustomStatus.REMEDIATED);
        
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95fee3");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(8409);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("fixed in build 300.845200451");
        fn.setBuildNumber("300.314668238163");
       fn.setIssue("CVE-2017-5929");
       fn.setSource("National Vulnerabilty Database");
       fn.setCvecvss3(new BigDecimal("9.8"));
      // fn.setCvecvss2("7.5");
       fn.setCwecwe(new BigDecimal("502"));
       fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
       fn.setName("jquery");
       fn.setGroup("ch.qos.logback");
       fn.setVersion("1.1.11");
       fn.setEffectiveLicense("MIT");
       fn.setCataloged("2 years ago");
       fn.setMatchState("Exact");
       fn.setIdentificationSource("Sonatype");
       fn.setWebsite("http://tomcat.apache.org");
     //  fn.setTest("sample");
     //  fn.setCvecvss2("7.5");
   //    fn.setSonatypecvss3("9.8");
       // fn.setCvss2("7.5");
        //fn.setCwecwe("502");
      /*  fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setCustomStatus(CustomStatus.REMEDIATED);
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95fe11");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95fe11/00000002.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(1001);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("fixed in build 300.845200451");
        fn.setBuildNumber("300.314668238163");
        fn.setIssue("CVE-2017-5929");
        fn.setSource("National Vulnerabilty Database");
      //  fn.setCvecvss3("9.8");
      //  fn.setCvecvss2("7.5");
       // fn.setCvecvss2("7.5");
        //fn.setSonatypecvss3("9.8");
        /*  fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setCustomStatus(CustomStatus.REMEDIATED);
        fn.setCwecwe(new BigDecimal("502"));
        fn.setName("jquery");
        fn.setGroup("ch.qos.logback");
        fn.setVersion("1.1.11");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
      //  fn.setTest("sample");
        fn.setMatchState("Exact");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95fe12");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95fe12/00000003.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(423);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("");
        fn.setBuildNumber("300.314668238163");
       fn.setIssue("CVE-2017-5929");
       fn.setSource("National Vulnerabilty Database");
       fn.setCvecvss3(new BigDecimal("9.8"));
      // fn.setCvecvss2("7.5");
       fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
      // fn.setCvecvss2("7.5");
     //  fn.setSonatypecvss3("9.8");
       /*  fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setName("jquery");
        fn.setGroup("ch.qos.logback");
        fn.setVersion("1.1.11");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
      //  fn.setTest("sample");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
        fn.setCustomStatus(CustomStatus.OPEN);
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95ffx5");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95ffx5/00000042.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(8409);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("fixed in build 300.845200451");
        fn.setBuildNumber("300.314668238163");
       fn.setIssue("CVE-2017-5929");
       fn.setName("jquery");
      // fn.setTest("sample");
       fn.setIdentificationSource("Sonatype");
       fn.setWebsite("http://tomcat.apache.org");
       fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
       fn.setSource("National Vulnerabilty Database");
       
       fn.setCvecvss3(new BigDecimal("9.8"));
     //  fn.setCvecvss2("7.5");
      // fn.setCvecvss2("7.5");
       // fn.setSonatypecvss3("9.8");
       /*  fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setCwecwe(new BigDecimal("502"));
        fn.setName("jquery");
        fn.setVersion("1.1.11");
        fn.setGroup("ch.qos.logback");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
        // fn.setTest("sample");
        fn.setCustomStatus(CustomStatus.REMEDIATED);
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95fe88");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95fe88/00000008.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(409);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95feag/00000012.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("");
        fn.setBuildNumber("300.314668238163");
        fn.setIssue("CVE-2017-5929");
        fn.setSource("National Vulner"
        		+ "abilty Database");
        fn.setCvecvss3(new BigDecimal("9.8"));
      //  fn.setCvecvss2("7.5");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
        fn.setName("jquery");
        fn.setVersion("1.1.11");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
      //  fn.setTest("sample");
      //  fn.setCvecvss2("7.5");
      //  fn.setSonatypecvss3("9.8");
        /* fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setCustomStatus(CustomStatus.NEW);
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95f111");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95f111/00000018.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(22);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95fe88/00000008.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("");
        fn.setBuildNumber("300.314668238163");
       fn.setIssue("CVE-2017-5929");
       fn.setSource("National Vulnerabilty Database");
       fn.setCvecvss3(new BigDecimal("9.8"));
      // fn.setCvecvss2("7.5");
       fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
    //   fn.setCvecvss2("7.5");
     //  fn.setSonatypecvss3("9.8");
       /* /* fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setCwecwe(new BigDecimal("502"));
        fn.setName("jquery");
        fn.setGroup("ch.qos.logback");
        fn.setVersion("1.1.11");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
        
      //  fn.setTest("sample");
        fn.setCustomStatus(CustomStatus.NEW);
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        fn = new Finding();
        // Mandatory custom attributes:
        fn.setUniqueId("c834c327-4cee-4420-b1f8-b24bea95fe55");
        // Builtin attributes:
        fn.setCategory("SQL Injection");
        fn.setFileName("file-c834c327-4cee-4420-b1f8-b24bea95fe55/00000007.bin");
        fn.setVulnerabilityAbstract("RubyGemsVersion between 2.0.0 and 2.6.13 are vulnerable to a possible remote code execution vulnerabilty.YAML deserialization of gem specifications can bypass white lists.Specially crafted serialized objects can possibly be used to escalate to remote code execution");
        fn.setLineNumber(112);
        fn.setConfidence(2.941967f);
        fn.setImpact(200.696f);
        fn.setPriority(GenPriority.High);
        // Custom attributes:
        fn.setCategoryId("c121");
        fn.setArtifact("artifact-c834c327-4cee-4420-b1f8-b24bea95fee3/00000002.jar");
        fn.setDescription("SQL injection is a code injection technique, used to attack data-driven applications, in which nefarious SQL statements are inserted into an entry field for execution (e.g. to dump the database contents to the attacker).[1] SQL injection must exploit a security vulnerability in an application's software, for example, when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements or user input is not strongly typed and unexpectedly executed. SQL injection is mostly known as an attack vector for websites but can be used to attack any type of SQL database.");
        fn.setComment("");
        fn.setBuildNumber("300.314668238163");
        fn.setIssue("CVE-2017-5929");
        fn.setSource("National Vulnerabilty Database");
        fn.setCvecvss3(new BigDecimal("9.8"));
      //  fn.setCvecvss2("7.5");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
       // fn.setTest("sample");
      //  fn.setCvecvss2("7.4");
        fn.setSonatypecvss3(new BigDecimal("9.8"));
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html");
        fn.setName("jquery");
        fn.setGroup("ch.qos.logback");
      /*  fn.setCvss3("9.8");
        fn.setCvss2("7.5");
        fn.setCwecwe("502");
        fn.setCweurl("https://cwe.mitre.org/data/definitions/502.html"); */
        fn.setReportUrl("http://iq-server.company.com/assets/index.html");
        fn.setCwecwe(new BigDecimal("502"));
        fn.setName("jquery");
        fn.setVersion("1.1.11");
        fn.setEffectiveLicense("MIT");
        fn.setCataloged("2 years ago");
        fn.setMatchState("Exact");
        fn.setIdentificationSource("Sonatype");
        fn.setWebsite("http://tomcat.apache.org");
      //  fn.setTest("sample");
        fn.setCustomStatus(CustomStatus.OPEN);
        fn.setLastChangeDate(DATE_DESERIALIZER.convert("2017-04-16T21:31:42.092Z"));
        fn.setArtifactBuildDate(DATE_DESERIALIZER.convert("2017-04-17T22:31:42.092Z"));
        fn.setTextBase64("Example of a text encoded in the original scan to Base64. \n" + longText);
        findingList.add(fn);

        return findingList;
    }

private static final String longText = "From Wikipedia: \n"+
    "\n"+
    "Computer security, also known as cyber security or IT security, is the protection of computer systems from the theft or damage to their hardware, software or information, as well as from disruption or misdirection of the services they provide. \n"+
    "\n"+
    "Cyber security includes controlling physical access to the hardware, as well as protecting against harm that may come via network access, data and code injection. Also, due to malpractice by operators, whether intentional, accidental, IT security is susceptible to being tricked into deviating from secure procedures through various methods.\n";

}
