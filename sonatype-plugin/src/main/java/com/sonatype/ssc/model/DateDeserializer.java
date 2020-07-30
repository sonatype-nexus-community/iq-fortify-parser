package com.sonatype.ssc.model;

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

import com.fasterxml.jackson.databind.util.StdConverter;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DateDeserializer extends StdConverter<String, Date> {
    private static final DateTimeFormatter[] DATE_TIME_FORMATTERS = {DateTimeFormatter.ISO_DATE_TIME};
    private static final Logger LOG = LoggerFactory.getLogger(DateDeserializer.class);

    @Override
    public Date convert(final String dateStr) {
        for (final DateTimeFormatter formatter : DATE_TIME_FORMATTERS) {
            final TemporalAccessor temporalAccessor;
            try {
                temporalAccessor = formatter.parse(dateStr);
            } catch (final DateTimeException e) {
                // try next parser
            	LOG.error("Unsupported date format: " + dateStr);
                continue;
            }
            final Instant instant;
            if (temporalAccessor.query(TemporalQueries.offset()) != null) {
                instant = OffsetDateTime.from(temporalAccessor).toInstant();
            } else {
                instant = LocalDateTime.from(temporalAccessor).toInstant(ZoneOffset.UTC);
            }
            return Date.from(instant);
        }
        // no parser worked
        throw new IllegalArgumentException("Unsupported date format: " + dateStr);
    }
}
