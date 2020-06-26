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
package com.sonatype.ssc.intsvc.util;

import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;

import com.sonatype.ssc.intsvc.constants.SonatypeConstants;

public final class LoggerUtil
{
  static RollingFileAppender fileAppender;

  private LoggerUtil() {
    throw new IllegalStateException("LoggerUtil class");
  }

  public static Logger getLogger(Logger log, String fileName, String logLevel) {

    switch (logLevel.toUpperCase()) {
      case "DEBUG":
        log.setLevel(Level.DEBUG);
        break;
      case "INFO":
        log.setLevel(Level.INFO);
        break;
      case "FATAL":
        log.setLevel(Level.FATAL);
        break;
      case "OFF":
        log.setLevel(Level.OFF);
        break;
      case "TRACE":
        log.setLevel(Level.TRACE);
        break;
      case "WARN":
        log.setLevel(Level.WARN);
        break;
      default:
        log.setLevel(Level.DEBUG);
        break;
    }
    PatternLayout layout = new PatternLayout("%d{ISO8601} [%t] %-5p %c %x - %m%n");

    log.addAppender(new ConsoleAppender(layout));

    try {
      if (fileName == null || fileName.isEmpty()) {
        fileName = "./Service.log";
      }

      fileAppender = new RollingFileAppender(layout, fileName);

      log.addAppender(fileAppender);

    }
    catch (FileNotFoundException e) {
      log.error(SonatypeConstants.ERR_LOG_FILE + e.getMessage());
    }
    catch (IOException e) {
      log.error(SonatypeConstants.ERR_LOG_FILE_IO + e.getMessage());
    }

    return log;
  }
}
