package com.sonatype.ssc.intsvc.util;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;

public class TestLoggerUtil {
  public static void initLogger(String logLevel) {
    final Logger rootLogger = Logger.getRootLogger();

    switch (logLevel.toUpperCase()) {
      case "DEBUG":
        rootLogger.setLevel(Level.DEBUG);
        break;
      case "INFO":
        rootLogger.setLevel(Level.INFO);
        break;
      case "FATAL":
        rootLogger.setLevel(Level.FATAL);
        break;
      case "OFF":
        rootLogger.setLevel(Level.OFF);
        break;
      case "TRACE":
        rootLogger.setLevel(Level.TRACE);
        break;
      case "WARN":
        rootLogger.setLevel(Level.WARN);
        break;
      default:
        rootLogger.setLevel(Level.DEBUG);
        break;
    }
    PatternLayout layout = new PatternLayout("%d{ISO8601} [%t] %-5p %c %x - %m%n");

    rootLogger.addAppender(new ConsoleAppender(layout));
  }

}
