// Copyright 2021-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.basic.tna.utils;

/*import java.io.IOException;
import java.io.InputStream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
*/
/*import org.onosproject.segmentrouting.config.SegmentRoutingDeviceConfig;
import org.stratumproject.basic.tna.inbandtelemetry.IntReportConfig;
import org.stratumproject.basic.tna.slicing.api.SlicingConfig;*/

//import static org.junit.Assert.fail;

/**
 * Test utilities.
 */
public final class TestUtils {
    /*private static final String INT_REPORT_CONFIG_KEY = "report";
    private static final String SR_CONFIG_KEY = "segmentrouting";
    private static final String SLICING_CONFIG_KEY = "slicing";

    private TestUtils() { }

    public static SegmentRoutingDeviceConfig getSrConfig(DeviceId deviceId, String filename)  {
        SegmentRoutingDeviceConfig srCfg = new SegmentRoutingDeviceConfig();
        InputStream jsonStream = TestUtils.class.getResourceAsStream(filename);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(jsonStream);
            srCfg.init(deviceId, SR_CONFIG_KEY, jsonNode, mapper, config -> { });
        } catch (IOException e) {
            fail("Got error when reading file " + filename + " : " + e.getMessage());
        }

        return srCfg;
    }

    public static IntReportConfig getIntReportConfig(ApplicationId appId, String filename) {
        IntReportConfig config = new IntReportConfig();
        InputStream jsonStream = TestUtils.class.getResourceAsStream(filename);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(jsonStream);
            config.init(appId, INT_REPORT_CONFIG_KEY, jsonNode, mapper, c -> { });
        } catch (Exception e) {
            fail("Got error when reading file " + filename + " : " + e.getMessage());
        }
        return config;
    }

    public static SlicingConfig getSlicingConfig(ApplicationId appId, String filename) {
        SlicingConfig config = new SlicingConfig();
        InputStream jsonStream = TestUtils.class.getResourceAsStream(filename);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = mapper.readTree(jsonStream);
            config.init(appId, SLICING_CONFIG_KEY, jsonNode, mapper, c -> { });
        } catch (Exception e) {
            fail("Got error when reading file " + filename + " : " + e.getMessage());
        }
        return config;
    }*/
}
