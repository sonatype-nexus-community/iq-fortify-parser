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

  public static final String CRON_EXPRESSION = "0 0/360 6 * * ?";

  public static final String IQ_PROJECT = "sonatypeProject";

  public static final String IQ_PROJECT_STAGE = "sonatypeProjectStage";

  public static final String SSC_APPLICATION = "fortifyApplication";

  public static final String SSC_APPLICATION_VERSION = "fortifyApplicationVersion";

  public static final String SAVE_MAPPING = "saveMapping";

  public static final String MSG_IQ_DATA_WRT = "Data written into JSON file: ";

  public static final String MSG_DATA_CMP = "Data upload complete.";

  public static final String MSG_TOT_CNT = "Total runs executed: ";

  public static final String MSG_IQ_CNT = "Data successfully loaded for : ";

  public static final String MSG_SSC_CNT = "Data uploaded for : ";

  public static final String MSG_READ_SSC = "Getting application id from SSC";

  public static final String MSG_READ_IQ = "Getting data from IQ Server for project: %s with phase: %s";

  public static final String MSG_EVL_SCAN_SAME = "Evaluation date of report and scan date of last load file is same, hence for %s with phase: %s, no new data is available for import";

  public static final String MSG_FINDINGS_SAME_COUNT = "Findings count is equal for %s with phase: %s, no new data is available for import";

  public static final String MSG_NO_REP = "No report available for: %s with phase: %s in IQ server";

  public static final String MSG_NO_IQ_PRJ = "No project: %s with phase: %s available in IQ server";

  public static final String MSG_SSC_UPL_DATA = "Uploading data in SSC";

  public static final String MSG_SSC_APP_CRT = "Creating application in SSC";

  public static final String MSG_DLT_FILE = "Deleted the load file: ";

  public static final String MSG_SCH_START = "Scheduler run started";

  public static final String MSG_SCH_END = "Scheduler run completed";

  public static final String MSG_SCH_TIME = "Scheduler run took ";

  public static final String MSG_SCH_SEPRATOR = "###############################################################################";

  public static final String MSG_READ_IQ_DATA = "Reading IQ data from report";

  public static final String MSG_WRITE_DATA = "Writing data into JSON file ::";

  public static final String MSG_GET_IQ_DATA = "Getting project data from IQ";

  public static final String ERR_SSC_APP_UPLOAD = "Error in startScanLoad while loading data in fortify::";

  public static final String ERR_IQ_PRJ = "Sonatype project name is missing from mapping JSON.";

  public static final String ERR_IQ_PRJ_STG = "Sonatype project stage is missing from mapping JSON.";

  public static final String ERR_SSC_APP = "Fortify application name is missing from mapping JSON.";

  public static final String ERR_SSC_APP_VER = "Fortify application version is missing from mapping JSON.";

  public static final String ERR_SSC_CREATE_APP = "Not able to found and create application in SSC server.";

  public static final String ERR_MISSING_JSON = "Mapping JSON file not found ::";

  public static final String ERR_IOEXCP_JSON = "IOException exception in reading mapping json ::";

  public static final String ERR_EXCP_JSON = "Exception occured while reading JSON file::";

  public static final String ERR_GET_IQ_DATA = "Error in getIQVulnerabilityData:";

  public static final String ERR_IQ_API = "Error while calling IQ API service::";

  public static final String ERR_SSC_API = "Error while calling SSC API service::";

  public static final String ERR_SSC_APP_ID = "Error in getSSCApplicationId: ";

  public static final String ERR_SSC_DATA_UPL = "Error while uploading the vulnerability to Fortify::";

  public static final String ERR_SSC_CRT_APP = "Error in getNewSSCApplicationId..";

  public static final String ERR_SSC_JSON = "Json Processing Exception in ..";

  public static final String ERR_SSC_EXCP = "Exception in update Attributes....";

  public static final String ERR_SSC_PRJ_EXP = "Exception in get ProjectId....";

  public static final String ERR_KILL_PRC = "Error in killing the process::";

  public static final String ERR_DLT_FILE = "Exception occured while deleting the load file: ";

  public static final String ERR_FILE_TKN = "Error while retrieving the file token for upload::";

  public static final String ERR_DLT_TKN = "Error while deleting the file token for upload::";

  public static final String ERR_GET_INT_APP_ID = "Error in getting internal application id from IQ: ";

  public static final String ERR_READ_MAP_JSON = "Error in reading the JSON: ";

  public static final String ERR_WRITE_LOAD = "Error while createJSON :: ";

  public static final String ERR_APP_DEACT = "The application in SSC is in de-active state hence cannot load vulnerabilities.";


  public static final String ERR_PRP_NOT_FND = "iqapplication.properties file not found ::";

  public static final String ERR_IO_EXCP = "IOException exception in reading iqapplication.properties ::";

  public static final String ERR_READ_PRP = "Error in reading properties file exiting the data load process.";

  public static final String ERR_MISS_PRP = "Missing required properties from iqapplication.properties.";

  public static final String ERR_LOG_FILE = "Incorrect log file location: ";

  public static final String ERR_LOG_FILE_IO = "IOException in log file location: ";

  public static final String ERR_IQ_URL_MISSING = "Missing IQ Server URL from iqapplication.properties, it's a required property.";

  public static final String ERR_IQ_USER_MISSING = "Missing IQ Server username from iqapplication.properties, it's a required property.";

  public static final String ERR_IQ_PASS_MISSING = "Missing IQ Server password from iqapplication.properties, it's a required property.";

  public static final String ERR_SSC_URL_MISSING = "Missing SSC Server URL from iqapplication.properties, it's a required property.";

  public static final String ERR_SSC_USER_OR_TOKEN_MISSING = "Missing SSC Server username or token from iqapplication.properties, it's a required property.";

  public static final String ERR_SSC_PASS_MISSING = "Missing SSC Server password from iqapplication.properties, it's a required property.";

  public static final String ERR_MAP_JSON_MISSING = "Missing IQ to SSC mapping file name from iqapplication.properties, it's a required property.";

  public static final String ERR_LOADFILE_LOCATION_CANT_READ = "loadfile location from iqapplication.properties points to a directory that can't be read, it's a required property to an existing directory: ";

  public static final String ERR_LOADFILE_LOCATION_CANT_WRITE = "loadfile location from iqapplication.properties points to a directory that can't be written to, it's a required property to a directory with write access: ";

  public static final String ERR_SSC_UPLOAD = "Error while uploading to SSC the load file: ";

  public static final String ERR_BKP_FILE = "Exception occured while renaming the load file : ";

  public static final String MSG_BKP_FILE = "Created backup of load file: ";
}
