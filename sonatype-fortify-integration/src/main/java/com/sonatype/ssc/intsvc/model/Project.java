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

public class Project
{
  private Long id;

  private String issueTemplateId;

  private String createdBy;

  private String description;

  private String name;

  public String getIssueTemplateId()
  {
    return issueTemplateId;
  }

  public void setIssueTemplateId(String issueTemplateId)
  {
    this.issueTemplateId = issueTemplateId;
  }

  public String getCreatedBy()
  {
    return createdBy;
  }

  public void setCreatedBy(String createdBy)
  {
    this.createdBy = createdBy;
  }

  public String getDescription()
  {
    return description;
  }

  public void setDescription(String description)
  {
    this.description = description;
  }

  public String getName()
  {
    return name;
  }

  public void setName(String name)
  {
    this.name = name;
  }

  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  @Override
  public String toString()
  {
    return "Project [issueTemplateId = " + issueTemplateId + ", createdBy = " + createdBy + ", description = " +
        description + ", name = " + name + "]";
  }

  public String toJSONString() {
    return "{\"id\":" + id + ",\"issueTemplateId\":\"" + issueTemplateId + "\",\"createdBy\":\"" + createdBy +
        "\",\"description\":\"" + description + "\",\"name\":\"" + name + "\"}";
  }
}
