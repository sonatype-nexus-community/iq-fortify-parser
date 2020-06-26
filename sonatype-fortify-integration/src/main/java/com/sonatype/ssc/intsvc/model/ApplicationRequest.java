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

public class ApplicationRequest
{
  private Project project;

  private String creationDate = "";

  private String issueTemplateId = "";

  private String masterAttrGuid = "";

  private String createdBy = "";

  private String status = "";

  private boolean committed;

  private String description = "";

  private String name = "";

  private String owner = "";

  private boolean active;

  public Project getProject()
  {
    return project;
  }

  public void setProject(Project project)
  {
    this.project = project;
  }

  public String getCreationDate()
  {
    return creationDate;
  }

  public void setCreationDate(String creationDate)
  {
    if (creationDate != null && creationDate.trim().length() > 0) {
      this.creationDate = creationDate;
    }
    else {
      this.creationDate = "";
    }
  }

  public String getIssueTemplateId()
  {
    return issueTemplateId;
  }

  public void setIssueTemplateId(String issueTemplateId)
  {
    if (issueTemplateId != null && issueTemplateId.trim().length() > 0) {
      this.issueTemplateId = issueTemplateId;
    }
    else {
      this.issueTemplateId = "";
    }
  }

  public String getMasterAttrGuid()
  {
    return masterAttrGuid;
  }

  public void setMasterAttrGuid(String masterAttrGuid)
  {
    if (masterAttrGuid != null && masterAttrGuid.trim().length() > 0) {
      this.masterAttrGuid = masterAttrGuid;
    }
    else {
      this.masterAttrGuid = "";
    }
  }

  public String getCreatedBy()
  {
    return createdBy;
  }

  public void setCreatedBy(String createdBy)
  {
    if (createdBy != null && createdBy.trim().length() > 0) {
      this.createdBy = createdBy;
    }
    else {
      this.createdBy = "";
    }
  }

  public String getStatus()
  {
    return status;
  }

  public void setStatus(String status)
  {
    if (status != null && status.trim().length() > 0) {
      this.status = status;
    }
    else {
      this.status = "";
    }
  }

  public boolean getCommitted()
  {
    return committed;
  }

  public void setCommitted(boolean committed)
  {
    this.committed = committed;
  }

  public String getDescription()
  {
    return description;
  }

  public void setDescription(String description)
  {
    if (description != null && description.trim().length() > 0) {
      this.description = description;
    }
    else {
      this.description = "";
    }
  }

  public String getName()
  {
    return name;
  }

  public void setName(String name)
  {
    if (name != null && name.trim().length() > 0) {
      this.name = name;
    }
    else {
      this.name = "";
    }
  }

  public String getOwner()
  {
    return owner;
  }

  public void setOwner(String owner)
  {
    if (owner != null && owner.trim().length() > 0) {
      this.owner = owner;
    }
    else {
      this.owner = "";
    }
  }

  public boolean getActive()
  {
    return active;
  }

  public void setActive(boolean active)
  {
    this.active = active;
  }

  @Override
  public String toString()
  {
    return "ApplicationRequest [project = " + project + ", creationDate = " + creationDate + ", issueTemplateId = " +
        issueTemplateId + ", masterAttrGuid = " + masterAttrGuid + ", createdBy = " + createdBy + ", status = " +
        status + ", committed = " + committed + ", description = " + description + ", name = " + name + ", owner = " +
        owner + ", active = " + active + "]";
  }

  public String toJSONString()
  {
    return "{\"project\":" + project.toJSONString() + ",\"creationDate\":\"" + creationDate +
        "\",\"issueTemplateId\":\"" + issueTemplateId + "\",\"masterAttrGuid\":\"" + masterAttrGuid +
        "\",\"createdBy\":\"" + createdBy + "\",\"status\":\"" + status + "\",\"committed\":" + committed +
        ",\"description\":\"" + description + "\",\"name\":\"" + name + "\",\"owner\":\"" + owner + "\",\"active\":" +
        active + "}";
  }
}
