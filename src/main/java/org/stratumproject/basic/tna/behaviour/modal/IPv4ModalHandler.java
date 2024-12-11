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


public class IPv4ModalHandler {
    private static final Logger log = getLogger(IPv4ModalHandler.class);
    
    public int transferIP2Host(int ipParam) {
        log.warn("transferIP2Host ipParam:{}", ipParam);
        int vmx = ((ipParam & 0xffff) >> 8) - 1;
        int i = (ipParam & 0xff) + 64 - 12;
        return vmx * 255 + i;
    }

    public FlowRule applyIPv4Flow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer) {
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId srcAddrFieldId = PiMatchFieldId.of("hdr.ipv4.srcAddr");
        PiMatchFieldId dstAddrFieldId = PiMatchFieldId.of("hdr.ipv4.dstAddr");

        byte[] srcIPv4Address = new byte[4];
        buffer.position(12);
        for(int i=0;i<4;i++) {
            srcIPv4Address[i] = buffer.get();
        }

        byte[] dstIPv4Address = new byte[4];
        buffer.position(16);
        for(int i=0;i<4;i++) {
            dstIPv4Address[i] = buffer.get();
        }

        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, 0x0800)
            .matchExact(srcAddrFieldId, srcIPv4Address)
            .matchExact(dstAddrFieldId, dstIPv4Address)
            .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .add(criteria)
            .build();
        PiTableAction piTableAction = PiAction.builder()
            .withId(PiActionId.of("ingress.set_next_v4_hop"))
            .withParameter(new PiActionParam(PiActionParamId.of("dst_port"), ImmutableByteSequence.copyFrom(port)))
            .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .piTableAction(piTableAction)
            .build();
        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.TABLEID_IPV4)
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