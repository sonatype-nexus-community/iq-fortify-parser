package com.sonatype.ssc.plugin;

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

/**
 * <P>
 * All custom vulnerability attributes must be defined in this class and must
 * implement {@link com.fortify.plugin.spi.VulnerabilityAttribute} interface .
 * <BR>
 * For all other attributes than custom ones which this parser needs see
 * {@link VulnAttribute}
 */
public enum SonatypeVulnAttribute implements com.fortify.plugin.spi.VulnerabilityAttribute {

  // Custom attributes must have their types defined:
  UNIQUE_ID(VulnAttribute.UNIQUE_ID.attrName(), AttrType.STRING),
//  CATEGORY_ID(VulnAttribute.CATEGORY_ID.attrName(), AttrType.STRING),
  ARTIFACT(VulnAttribute.ARTIFACT.attrName(), AttrType.STRING),
//  COMMENT(VulnAttribute.COMMENT.attrName(), AttrType.LONG_STRING),
//  DESCRIPTION(VulnAttribute.DESCRIPTION.attrName(), AttrType.LONG_STRING),
//  CUSTOM_STATUS(VulnAttribute.CUSTOM_STATUS.attrName(), AttrType.STRING),
  REPORT_URL(VulnAttribute.REPORT_URL.attrName(), AttrType.LONG_STRING),
  SOURCE(VulnAttribute.SOURCE.attrName(), AttrType.LONG_STRING),
  ISSUE(VulnAttribute.ISSUE.attrName(), AttrType.STRING),
  SONATYPETHREATLEVEL(VulnAttribute.SONATYPETHREATLEVEL.attrName(), AttrType.STRING),
  CVECVSS3(VulnAttribute.CVECVSS3.attrName(), AttrType.DECIMAL),
  CVECVSS2(VulnAttribute.CVECVSS2.attrName(), AttrType.DECIMAL),
  CWECWE(VulnAttribute.CWECWE.attrName(), AttrType.DECIMAL),
  SONATYPECVSS3(VulnAttribute.SONATYPECVSS3.attrName(), AttrType.DECIMAL),
  CWEURL(VulnAttribute.CWEURL.attrName(), AttrType.STRING),
  CVEURL(VulnAttribute.CVEURL.attrName(), AttrType.STRING),
  GROUP(VulnAttribute.GROUP.attrName(), AttrType.STRING),
  VERSION(VulnAttribute.VERSION.attrName(), AttrType.STRING),
//  RECOMMENDED_VERSION(VulnAttribute.RECOMMENDED_VERSION.attrName(), AttrType.STRING),
//  EFFECTIVE_LICENSE(VulnAttribute.EFFECTIVE_LICENSE.attrName(),AttrType.STRING),
//  CATALOGED(VulnAttribute.CATALOGED.attrName(),AttrType.STRING),
//  MATCHSTATE(VulnAttribute.MATCHSTATE.attrName(),AttrType.STRING),
//  IDENTIFICATION_SOURCE(VulnAttribute.IDENTIFICATION_SOURCE.attrName(),AttrType.STRING),
//  WEBSITE(VulnAttribute.WEBSITE.attrName(),AttrType.STRING),

  ;

  private final AttrType attributeType;
  private final String attributeName;

  private SonatypeVulnAttribute(final String attributeName, final AttrType attributeType) {
    this.attributeType = attributeType;
    this.attributeName = attributeName;
  }

  @Override
  public String attributeName() {
    return attributeName;
  }

  @Override
  public AttrType attributeType() {
    return attributeType;
  }
}
