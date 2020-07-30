package com.sonatype.ssc.plugin;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class TestVulnAttribute {
  private final VulnAttribute LAST_BUILT_IN = VulnAttribute.PRIORITY;

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
        // check that there is a SonatypeVulnAttribute associated
        SonatypeVulnAttribute sva = svas.remove(va.attrName());
        assertNotNull("missing SonatypeVunlAttribute for VulnAttribute " + va.attrName(), sva);
      }
    }
    assertEquals(svas.size() + " SonatypeVulnAttribute(s) created without VulnAttribute: " + svas, 0, svas.size());
  }
}
