package org.stratumproject.basic.tna.behaviour;

import java.nio.ByteBuffer;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.slf4j.Logger;

import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.slf4j.LoggerFactory.getLogger;

public class GEOModalHandler {
    private static final Logger log = getLogger(GEOModalHandler.class);

    public int transferGEO2Host(int lat, int lon) {
        log.warn("transferGEO2Host lat:{}, lon:{}", lat, lon);
        int i = lat + 63;
        int sign = ((lon >> 30) & 3) == 1 ? -1 : 1;
        int integerPart = ((lon >> 15) & 0x7fff);
        int fractionPart = Math.round((lon & 0x7fff) * 10.0f / 32767);
        log.warn("geolatlon, sign:{}, integer:{}, fraction:{}", sign, integerPart, fractionPart);
        double tmp = (integerPart + fractionPart * 1.0 / 10) * sign;
        int vmx = (int) Math.round(((tmp + 180) - (i - 64) * 0.4) / 20);
        return vmx * 255 + i;
    }

    public FlowRule applyGEOFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId geoAreaPosLatFieldId = PiMatchFieldId.of("hdr.gbc.geo_area_pos_lat");
        PiMatchFieldId geoAreaPosLonFieldId = PiMatchFieldId.of("hdr.gbc.geo_area_pos_lon");
        PiMatchFieldId disaFieldId = PiMatchFieldId.of("hdr.gbc.disa");
        PiMatchFieldId disbFieldId = PiMatchFieldId.of("hdr.gbc.disb");
        
        byte[] geoAreaPosLat = new byte[4];
        buffer.position(40);
        for(int i=0;i<4;i++) {
            geoAreaPosLat[i] = buffer.get();
        }
        
        byte[] geoAreaPosLon = new byte[4];
        buffer.position(44);
        for(int i=0;i<4;i++) {
            geoAreaPosLon[i] = buffer.get();
        }
        
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, 0x8947)
            .matchExact(geoAreaPosLatFieldId, geoAreaPosLat)
            .matchExact(geoAreaPosLonFieldId, geoAreaPosLon)
            .matchExact(disaFieldId, new byte[]{0})
            .matchExact(disbFieldId, new byte[]{0})
            .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .add(criteria)
            .build();
        PiTableAction piTableAction = PiAction.builder()
            .withId(PiActionId.of("ingress.geo_ucast_route"))
            .withParameter(new PiActionParam(PiActionParamId.of("dst_port"), ImmutableByteSequence.copyFrom(port)))
            .build();                
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .piTableAction(piTableAction)
            .build();
        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.TABLEID_GEO)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }
}