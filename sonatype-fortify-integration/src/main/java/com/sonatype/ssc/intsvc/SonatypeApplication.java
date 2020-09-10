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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;
import com.sonatype.ssc.intsvc.service.IQFortifyIntegrationService;
import com.sonatype.ssc.intsvc.util.ApplicationPropertiesLoader;
import com.sonatype.ssc.intsvc.util.LoggerUtil;

import org.springframework.beans.factory.annotation.Value;

@SpringBootApplication
@EnableScheduling
@Configuration
@PropertySource("file:iqapplication.properties")
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class, HibernateJpaAutoConfiguration.class})
public class SonatypeApplication
{
  @Autowired
  private IQFortifyIntegrationService iqFortifyIntgSrv;

  private static final Logger logger = Logger.getRootLogger();

  @Value("${scheduling.job.cron}")
  private String schedulerCron;

  @Value("${logfile.location:./Service.log}")
  private String logfileLocation;

  @Value("${logLevel:DEBUG}")
  private String logLevel;

  /**
   * This is the main method which runs Sonatype spring application.
   *
   * @param args Unused.
   * @return Nothing.
   */
  public static void main(String[] args) {
    SpringApplication.run(SonatypeApplication.class);
  }

  /**
   * This method is scheduled as defined in configuration file.
   */
  @Scheduled(cron = "${scheduling.job.cron}")
  public void runLoad() {
    long start = System.currentTimeMillis();
    Logger log = LoggerUtil.getLogger(logger, logfileLocation, logLevel);

    try {
      ApplicationProperties appProp = ApplicationPropertiesLoader.loadProperties();
      if (appProp == null) {
        log = LoggerUtil.getLogger(logger, "", "");
        log.error(SonatypeConstants.ERR_READ_PRP);
        iqFortifyIntgSrv.killProcess();
        log.fatal("process should have been killed...");
        return;
      }
      if (appProp.getMissingReqProp()) {
        log.error(SonatypeConstants.ERR_READ_PRP);
        iqFortifyIntgSrv.killProcess();
        log.fatal("process should have been killed...");
        return;
      }

      log.info(SonatypeConstants.MSG_SCH_START);
      iqFortifyIntgSrv.startLoad(appProp);

      log.info(SonatypeConstants.MSG_SCH_END);
      long end = System.currentTimeMillis();
      log.info(SonatypeConstants.MSG_SCH_TIME + (end - start) / 1000 + " seconds");
      log.info(SonatypeConstants.MSG_SCH_SEPRATOR);

      if (appProp.getIsKillTrue()) {
        iqFortifyIntgSrv.killProcess();
        log.fatal("process should have been killed...");
        return;
      }
    }
    catch (FileNotFoundException e) {
      log.error(SonatypeConstants.ERR_PRP_NOT_FND + e.getMessage());
      log.info(SonatypeConstants.MSG_SCH_SEPRATOR);
    }
    catch (IOException e) {
      log.error(SonatypeConstants.ERR_IO_EXCP + e.getMessage());
      log.info(SonatypeConstants.MSG_SCH_SEPRATOR);
    }
    finally {
      log.removeAllAppenders();
    }
  }
}
