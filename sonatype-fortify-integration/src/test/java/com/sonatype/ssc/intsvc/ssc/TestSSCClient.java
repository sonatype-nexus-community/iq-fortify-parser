package com.sonatype.ssc.intsvc.ssc;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestSSCClient {

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

}
