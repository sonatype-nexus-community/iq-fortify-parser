/*
 * Copyright (c) 2016-present Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package com.sonatype.ssc.intsvc;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.log4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import com.sonatype.ssc.intsvc.model.IQProperties;
import com.sonatype.ssc.intsvc.service.IQFortifyIntegrationService;
import com.sonatype.ssc.intsvc.util.ApplicationProperty;

import static org.junit.Assert.assertNotNull;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = TestApplication.class)
@ContextConfiguration(classes = IQFortifyIntegrationService.class)
public class TestSonatypeController
{
  @Autowired
  private IQFortifyIntegrationService iqFortifyIntgSrv;

  private static final Logger logger = Logger.getRootLogger();

  @Test
  public void testStartScanLoad() {
    IQProperties myProp = null;
    try {
      myProp = ApplicationProperty.loadProperties();

      assertNotNull("Iq Server field is null...", myProp.getIqServer());
      assertNotNull("Iq Server password field is null...", myProp.getIqServerPassword());
      assertNotNull("Load Location field is null...", myProp.getLoadLocation());
      assertNotNull("Fortify Server field is  null...", myProp.getSscServer());
      assertNotNull("Fortify Password field is  null...", myProp.getSscServerPassword());
      assertNotNull("Load location field is  null...", myProp.getLoadLocation());
    }
    catch (FileNotFoundException e) {
      logger.error(e.getMessage());
    }
    catch (IOException e) {
      logger.error("IOException exception:" + e.getMessage());
    }
    if (myProp.getMissingReqProp()) {
      try {
        iqFortifyIntgSrv.startLoad(myProp, null, false);
      }
      catch (IOException e) {
        logger.error(e.getMessage());
      }
    }
  }
}
