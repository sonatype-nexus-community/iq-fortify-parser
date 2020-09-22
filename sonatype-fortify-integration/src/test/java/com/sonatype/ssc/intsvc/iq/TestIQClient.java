package com.sonatype.ssc.intsvc.iq;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestIQClient {

  @Test
  public void testUrlWithTrailingSlash() {
    try (IQClient client = new IQClient("http://localhost:8070/", "user", "token", "raw")) {
      assertEquals("http://localhost:8070/ui/links/vln/vuln", client.getVulnDetailURL("vuln"));
    }
  }

  @Test
  public void testUrlWithoutTrailingSlash() {
    try (IQClient client = new IQClient("http://localhost:8070", "user", "token", "raw")) {
      assertEquals("http://localhost:8070/ui/links/vln/vuln", client.getVulnDetailURL("vuln"));
    }
  }
}
