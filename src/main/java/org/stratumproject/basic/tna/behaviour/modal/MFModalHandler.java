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

public class MFModalHandler {
    private static final Logger log = getLogger(MFModalHandler.class);

    public int transferMF2Host(int mfParam) {
        log.warn("transferMF2Host mfParam:{}", mfParam);
        int vmx = mfParam / 1000;
        int i = mfParam - 1 - vmx * 1000 + 64;
        return vmx * 255 + i;
    }

    public FlowRule applyMFFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId srcGuidFieldId = PiMatchFieldId.of("hdr.mf.src_guid");
        PiMatchFieldId dstGuidFieldId = PiMatchFieldId.of("hdr.mf.dst_guid");
        
        byte[] srcMFGuid = new byte[4];
        buffer.position(4);
        for(int i=0;i<4;i++) {
            srcMFGuid[i] = buffer.get();
        }
        
        byte[] dstMFGuid = new byte[4];
        buffer.position(8);
        for(int i=0;i<4;i++) {
            dstMFGuid[i] = buffer.get();
        }
        
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, 0x27c0)
            .matchExact(srcGuidFieldId, srcMFGuid)
            .matchExact(dstGuidFieldId, dstMFGuid)
            .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .add(criteria)
            .build();
        PiTableAction piTableAction = PiAction.builder()
            .withId(PiActionId.of("ingress.set_next_mf_hop"))
            .withParameter(new PiActionParam(PiActionParamId.of("dst_port"), ImmutableByteSequence.copyFrom(port)))
            .build();                
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .piTableAction(piTableAction)
            .build();
        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.TABLEID_MF)
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