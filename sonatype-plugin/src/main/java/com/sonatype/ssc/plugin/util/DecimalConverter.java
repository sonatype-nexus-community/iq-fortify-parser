package com.sonatype.ssc.plugin.util;

/**
 * (c) Copyright Sonatype Inc. 2018
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.math.BigDecimal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DecimalConverter {

  private static final Logger LOG = LoggerFactory.getLogger(DecimalConverter.class);

  private DecimalConverter() {
    throw new IllegalStateException("DecimalConverter class");
  }

  public static String convertToString(BigDecimal bDecimal) {
    String convertedStr = "";
    try {
      convertedStr = bDecimal.toString();
      return convertedStr;
    } catch (Exception e) {
      LOG.error("Error while converting big decimal to string: " + e.getMessage());
      return "";
    }

  }

  public static BigDecimal convertToBigDecimal(String str) {
    BigDecimal bigDecimal = new BigDecimal("0.0");
    try {
      bigDecimal = new BigDecimal(str);
      return bigDecimal;
    } catch (Exception e) {
      LOG.error("Error while converting string to big decimal: " + e.getMessage());
      return null;
    }
  }
}
