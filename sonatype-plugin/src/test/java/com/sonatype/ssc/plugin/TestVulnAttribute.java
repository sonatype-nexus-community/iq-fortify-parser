package com.sonatype.ssc.plugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sonatype.ssc.model.Finding;
import com.sonatype.ssc.model.Scan;

public class TestVulnAttribute {
  private final VulnAttribute LAST_BUILT_IN = VulnAttribute.PRIORITY;

  /**
   * Test consistency between VulnAttribute and SonatypeVulnAttribute
   */
  @Test
  public void testVulnAttribute() {
    Map<String, SonatypeVulnAttribute> svas = new HashMap<>();
    for (SonatypeVulnAttribute sva : SonatypeVulnAttribute.values()) {
      svas.put(sva.attributeName(), sva);
    }

    boolean builtin = true;
    for (VulnAttribute va : VulnAttribute.values()) {
      if (builtin) {
        if (va == LAST_BUILT_IN) {
          builtin = false;
        }
      } else {
        // check that there is a SonatypeVulnAttribute associated to every custom field of VulnAttribute
        SonatypeVulnAttribute sva = svas.remove(va.attrName());
        assertNotNull("missing SonatypeVunlAttribute for VulnAttribute " + va.attrName(), sva);
      }
    }
    // check that every SonatypeVulnAttribute has corresponding VulnAttribute
    assertEquals(svas.size() + " SonatypeVulnAttribute(s) created without VulnAttribute: " + svas, 0, svas.size());
  }

  /**
   * Test consistency between model's scan+finding and VulnAttribute.
   */
  @Test
  public void testScanFinding() {
    Set<String> fields = new HashSet<>();

    // Scan
    for (Field f : FieldUtils.getAllFields(Scan.class)) {
      if ("findings".equals(f.getName())) {
        // ignore "findings", that is not really a field
        continue;
      }
      VulnAttribute va = VulnAttribute.get(f.getName());
      assertNotNull("missing VulnAttribute for Scan field " + f.getName(), va);
      fields.add(f.getName());
    }

    // Finding
    for (Field f : FieldUtils.getAllFields(Finding.class)) {
      VulnAttribute va = VulnAttribute.get(f.getName());
      assertNotNull("missing VulnAttribute for Finding field " + f.getName(), va);
      fields.add(f.getName());
    }

    // check VulnAtttributes without associated field in Scan or Finding
    for (VulnAttribute va : VulnAttribute.values()) {
      assertNotNull("VulnAttribute without Scan or Finding field: " + va.attrName(), fields.contains(va.attrName()));
    }
  }

  // TODO check what fields should simply be dropped...
  private static final String[] EXPECTED_UNUSED = { "description", "recommendedVersion", "customStatus", "comment",
      "uniqueId", "categoryId" };

  /**
   * Test that fields are used in the SSC plugin template
   * @throws IOException 
   */
  @Test
  public void testTemplate() throws IOException {
    Set<String> unused = new HashSet<>();
    for (SonatypeVulnAttribute sva : SonatypeVulnAttribute.values()) {
      unused.add(sva.attributeName());
    }

    ObjectMapper mapper = new ObjectMapper();
    JsonNode root = mapper.readTree(this.getClass().getResourceAsStream("/viewtemplate/SonatypeTemplate.json"));

    for(JsonNode key: root.findValues("key")) {
      String field = key.asText();
      if (field.startsWith("customAttributes.")) {
        field = field.substring("customAttributes.".length());
        assertNotNull("unknown custom field in template: " + field, unused.remove(field));
      }
    }

    for(String expected: EXPECTED_UNUSED) {
      assertNotNull("unknown expected unused field: " + expected, unused.remove(expected));
    }

    assertEquals("unexpected " + unused.size() + " unused field(s): " + unused, 0, unused.size());
  }
}
