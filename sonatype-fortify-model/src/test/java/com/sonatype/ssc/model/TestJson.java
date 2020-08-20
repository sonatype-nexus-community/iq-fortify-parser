package com.sonatype.ssc.model;

import java.io.File;

import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

public class TestJson {

  /**
   * Test consistency between VulnAttribute and SonatypeVulnAttribute
   */
  @Test
  public void testVulnAttribute() throws Exception {
    ObjectMapper mapper = new ObjectMapper();

    Scan scan = mapper.readValue(this.getClass().getResource("sample-scan.json"), Scan.class);

    // https://github.com/FasterXML/jackson-databind/wiki/Serialization-Features
    mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
    mapper.writeValue(new File("target/sample-scan.json"), scan);
    // mapper.writeValueAsString(value);
  }
}
