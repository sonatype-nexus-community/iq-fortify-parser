package com.sonatype.ssc.intsvc.ssc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.sonatype.ssc.intsvc.util.TestLoggerUtil;

public class TestSSCClient {
  static {
    TestLoggerUtil.initLogger("DEBUG");
  }

  @Test
  public void testUrlWithTrailingSlash() {
    try (SSCClient client = new SSCClient("http://localhost:8088/ssc/", "token")) {
      assertEquals("http://localhost:8088/ssc/api/v1/project", client.getApiUrl("api/v1/project"));
    }
  }

  @Test
  public void testUrlWithoutTrailingSlash() {
    try (SSCClient client = new SSCClient("http://localhost:8088/ssc", "token")) {
      assertEquals("http://localhost:8088/ssc/api/v1/project", client.getApiUrl("api/v1/project"));
    }
  }

  @Test
  public void testGetSSCApplicationId() {
    String token = "Y2UxM2IyYjQtZjdjZS00MGVlLWE2YTMtYWM4ODMyODQ0NDA1"; // replace with your real CIToken token
    String appName = "Web application"; // from basic SSC demo
    String version = "1.0";
    try (SSCClient client = new SSCClient("http://localhost:8088/ssc", token)) {
      //long appId = client.getSSCApplicationId(appName, version);
      //assertTrue("should find SSC application '" + appName + "' version '" + version + "', but got id = " + appId, appId > 0);
    }
  }
}
