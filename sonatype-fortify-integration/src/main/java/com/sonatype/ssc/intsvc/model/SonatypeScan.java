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
package com.sonatype.ssc.intsvc.model;

/**
 * Sonatype scan result that will be sent to SSC
 */
public class SonatypeScan
{
  private int numberOfFiles;
  private String scanDate;
  private String buildServer;

  public int getNumberOfFiles() {
    return numberOfFiles;
  }

  public void setNumberOfFiles(final int numberOfFiles) {
    this.numberOfFiles = numberOfFiles;
  }

  public String getScanDate() {
    return scanDate;
  }

  public void setScanDate(String scanDate) {
    this.scanDate = scanDate;
  }

  public String getBuildServer() {
    return buildServer;
  }

  public void setBuildServer(String buildServer) {
    this.buildServer = buildServer;
  }
}
