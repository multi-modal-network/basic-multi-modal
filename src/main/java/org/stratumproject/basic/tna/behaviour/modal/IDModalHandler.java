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

public class IDModalHandler {
    private static final Logger log = getLogger(IDModalHandler.class);

    public int transferID2Host(int idParam) {
        log.warn("transferID2Host idParam:{}",idParam);
        int vmx = (idParam - 202271720) / 100000;
        int i = idParam - 202271720 - vmx * 100000 + 64;
        return vmx * 255 + i;
    }

    public FlowRule applyIDFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId srcIdentityFieldId = PiMatchFieldId.of("hdr.id.src_identity");
        PiMatchFieldId dstIdentityFieldId = PiMatchFieldId.of("hdr.id.dst_identity");

        byte[] srcIdentity = new byte[4];
        buffer.position(0);
        for(int i=0;i<4;i++) {
            srcIdentity[i] = buffer.get();
        }

        byte[] dstIdentity = new byte[4];
        buffer.position(4);
        for(int i=0;i<4;i++) {
            dstIdentity[i] = buffer.get();
        }

        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, 0x0812)
            .matchExact(srcIdentityFieldId, srcIdentity)
            .matchExact(dstIdentityFieldId, dstIdentity)
            .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .add(criteria)
            .build();
        PiTableAction piTableAction = PiAction.builder()
            .withId(PiActionId.of("ingress.set_next_id_hop"))
            .withParameter(new PiActionParam(PiActionParamId.of("dst_port"), ImmutableByteSequence.copyFrom(port)))
            .build();
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .piTableAction(piTableAction)
            .build();
        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.TABLEID_ID)
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