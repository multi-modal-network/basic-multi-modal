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

public class NDNModalHandler {
    private static final Logger log = getLogger(NDNModalHandler.class);

    public int transferNDN2Host(int param) {
        log.warn("transferNDN2Host param:{}", param);
        int vmx = (param - 202271720) / 100000;
        int i = param - 202271720 - vmx * 100000 + 64;
        return vmx * 100 + i;
    }

    public FlowRule applyNDNFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer) {
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId ndnCodeFieldId = PiMatchFieldId.of("hdr.ndn.ndn_prefix.code");
        PiMatchFieldId srcNDNNameFieldId = PiMatchFieldId.of("hdr.ndn.name_tlv.components[0].value");
        PiMatchFieldId dstNDNNameFieldId = PiMatchFieldId.of("hdr.ndn.name_tlv.components[1].value");
        PiMatchFieldId ndnContentFieldId = PiMatchFieldId.of("hdr.ndn.content_tlv.value");
        
        byte[] srcNDNName = new byte[4];
        buffer.position(8);
        for(int i=0;i<4;i++) {
            srcNDNName[i] = buffer.get();
        }
        
        byte[] dstNDNName = new byte[4];
        buffer.position(14);
        for(int i=0;i<4;i++) {
            dstNDNName[i] = buffer.get();
        }
        
        byte[] ndnContent = new byte[2];
        buffer.position(34);
        for(int i=0;i<2;i++) {
            ndnContent[i] = buffer.get();
        }
        
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, 0x8624)
            .matchExact(ndnCodeFieldId, 6)
            .matchExact(srcNDNNameFieldId, srcNDNName)
            .matchExact(dstNDNNameFieldId, dstNDNName)
            .matchExact(ndnContentFieldId, ndnContent)
            .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .add(criteria)
            .build();
        PiTableAction piTableAction = PiAction.builder()
            .withId(PiActionId.of("ingress.set_next_ndn_hop"))
            .withParameter(new PiActionParam(PiActionParamId.of("dst_port"), ImmutableByteSequence.copyFrom(port)))
            .build();                
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .piTableAction(piTableAction)
            .build();
        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.TABLEID_NDN)
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