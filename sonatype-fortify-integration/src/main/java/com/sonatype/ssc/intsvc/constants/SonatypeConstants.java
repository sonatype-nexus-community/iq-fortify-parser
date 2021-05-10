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
package com.sonatype.ssc.intsvc.constants;

public final class SonatypeConstants
{
  private SonatypeConstants() {
    throw new IllegalStateException("SonatypeConstants class");
  }

  public static final String SSC_APPLICATION_DESCRIPTION = "Created by Sonatype IQ SSC integration service";

  public static final String SSC_APPLICATION_TEMPLATE_ID = "Prioritized-HighRisk-Project-Template";

  public static final String SSC_APPLICATION_CREATED_BY = "Sonatype IQ SSC integration service";

  public static final String SSC_APPLICATION_ACTIVE = "ACTIVE";

  public static final String MSG_READ_SSC = "Getting application id from SSC";

  public static final String MSG_SSC_APP_CRT = "Creating application in SSC";

  public static final String ERR_IQ_API = "Error while calling IQ API service::";

  public static final String ERR_SSC_API = "Error while calling SSC API service::";

  public static final String ERR_SSC_APP_ID = "Error in getSSCApplicationId: ";

  public static final String ERR_SSC_DATA_UPL = "Error while uploading the vulnerability to Fortify::";

  public static final String ERR_SSC_CRT_APP = "Error in getNewSSCApplicationId..";

  public static final String ERR_SSC_JSON = "Json Processing Exception in ..";

  public static final String ERR_SSC_EXCP = "Exception in update Attributes....";

  public static final String ERR_SSC_PRJ_EXP = "Exception in get ProjectId....";

  public static final String ERR_DLT_FILE = "Exception occured while deleting the load file: ";

  public static final String ERR_FILE_TKN = "Error while retrieving the file token for upload::";

  public static final String ERR_DLT_TKN = "Error while deleting the file token for upload::";

  public static final String ERR_GET_INT_APP_ID = "Error in getting internal application id from IQ: ";

  public static final String ERR_APP_DEACT = "The application in SSC is in de-active state hence cannot load vulnerabilities.";

  public static final String ERR_LOG_FILE = "Incorrect log file location: ";

  public static final String ERR_LOG_FILE_IO = "IOException in log file location: ";

  public static final String ERR_SSC_UPLOAD = "Error while uploading to SSC the load file: ";

}
