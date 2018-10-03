package com.thirdparty;

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

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * <P>All attributes used by parser and generator should be defined in this class.
 * <BR>We don't define attribute types here because we don't want this class to be dependent on plugin-api.
 * <BR>Mandatory custom issue attribute types should be defined in the class implementing VulnAttribute interface.
 */
enum VulnAttribute {

    // Top level built-in attribute names:
    ENGINE_VERSION("engineVersion"),
    SCAN_DATE("scanDate"),
    BUILD_SERVER("buildServer"),
    ELAPSED("elapsed"),

    // Issue built-in attribute names:
    CATEGORY("category"),
    FILE_NAME("fileName"),
    VULNERABILITY_ABSTRACT("vulnerabilityAbstract"),
    LINE_NUMBER("lineNumber"),
    CONFIDENCE("confidence"),
    IMPACT("impact"),
    PRIORITY("priority"),

    // Custom issue attribute names
    // Their mandatory types for this parser are defined in CustomVulnAttribute
    UNIQUE_ID("uniqueId"),
    CATEGORY_ID("categoryId"),
    ARTIFACT("artifact"),
    COMMENT("comment"),
    DESCRIPTION("description"),
    BUILD_NUMBER("buildNumber"),
    CUSTOM_STATUS("customStatus"),
    LAST_CHANGE_DATE("lastChangeDate"),
    ARTIFACT_BUILD_DATE("artifactBuildDate"),
    TEXT_BASE64("textBase64"),
    REPORT_URL("reportUrl"),
    ISSUE("issue"),
    CVECVSS3("cvecvss3"),
    CVECVSS2("cvecvss2"),
    SONATYPECVSS3("sonatypecvss3"),
	SOURCE("source"),
	CWECWE("cwecwe"),
	CWEURL("cweurl"),
	CVEURL("cveurl"),
	NAME("name"),
	GROUP("group"),
	VERSION("version"),
	EFFECTIVE_LICENSE("effectiveLicense"),
	CATALOGED("cataloged"),
	MATCHSTATE("matchState"),
	IDENTIFICATION_SOURCE("identificationSource"),
	WEBSITE("website"),
    ;

    private final String attrName;
    private static final Map<String, VulnAttribute> lookup =
            new HashMap<>();

    static {
        for(VulnAttribute s : EnumSet.allOf(VulnAttribute.class))
            lookup.put(s.attrName(), s);
    }

    VulnAttribute(final String attrName) {
        this.attrName = attrName;
    }

    public String attrName() {
        return attrName;
    }

    public static VulnAttribute get(String attrName) {
        try {
            return lookup.get(attrName);
        } catch (Exception e) {
            return null;
        }
    }
}