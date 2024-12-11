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


public class FlexIPModalHandler {
    private static final Logger log = getLogger(FlexIPModalHandler.class);

    // ---------------------FlexIP模态---------------------
    private static final int FLEXIP_OFFSET_F0 = 2048;
    private static final int FLEXIP_OFFSET_F1 = 202271720;
    private static final long FLEXIP_OFFSET_F2 = 1L << 50;

    private static final int FLEXIP_GAP_F0 = 100;
    private static final int FLEXIP_GAP_F1 = 100000;
    private static final long FLEXIP_GAP_F2 = 100000000L;
    private static final long FLEXIP_GAP_F4 = 100000000000L;

    private static final int RESTRAINED = 0;
    private static final int EXTENDABLE = 1;
    private static final int HIERARCHICAL = 2;
    private static final int MULTISEMANTICS = 3;

    private int processExtendableFormat(ByteBuffer buffer) {
        int host = 0;
        int index = buffer.get() & 0xff;
        switch (index) {
            case 0xf0:
                host = processF0(buffer);
                break;
            case 0xf1:
                host = processF1(buffer);
                break;
            case 0xf2:
                host = processF2(buffer);
                break;
            case 0xf4:
                host = processF4(buffer);
                break;
            default:
                break;
        }
        return host;
    }

    private int processHierarchicalFormat(ByteBuffer buffer) {
        int host = 0;
        int index = buffer.get() & 0xff;
        int afterByte = buffer.get() & 0xff;
        switch (afterByte) {
            case 0xf0:
                host = processF0(buffer);
                break;
            case 0xf1:
                host = processF1(buffer);
                break;
            case 0xf2:
                host = processF2(buffer);
                break;
            default:
                // todo: vmx标记
                int vmx = 1;
                host = vmx * 100 + afterByte;
                break;
        }
        return host;
    }

    private int processF0(ByteBuffer buffer) {
        byte[] FlexIP = new byte[2];
        buffer.get(FlexIP, 0, 2);
        int flexip = ((FlexIP[0] & 0xff) << 8) + (FlexIP[1] & 0xff);
        return calculateHost(flexip, FLEXIP_OFFSET_F0, FLEXIP_GAP_F0);
    }

    private int processF1(ByteBuffer buffer) {
        byte[] FlexIP = new byte[4];
        buffer.get(FlexIP, 0, 4);
        int flexip = ((FlexIP[0] & 0xff) << 24) + 
                     ((FlexIP[1] & 0xff) << 16) + 
                     ((FlexIP[2] & 0xff) << 8) + 
                     (FlexIP[3] & 0xff);
        return calculateHost(flexip, FLEXIP_OFFSET_F1, FLEXIP_GAP_F1);
    }

    private int processF2(ByteBuffer buffer) {
        byte[] FlexIP = new byte[8];
        buffer.get(FlexIP, 0, 8);
        long flexip = (((long)FlexIP[0] & 0xff) << 56) +
                        (((long)FlexIP[1] & 0xff) << 48) + 
                        (((long)FlexIP[2] & 0xff) << 40) + 
                        (((long)FlexIP[3] & 0xff) << 32) +
                        (((long)FlexIP[4] & 0xff) << 24) + 
                        (((long)FlexIP[5] & 0xff) << 16) + 
                        (((long)FlexIP[6] & 0xff) << 8) + 
                        ((long)FlexIP[7] & 0xff);
        return calculateHost(flexip, FLEXIP_OFFSET_F2, FLEXIP_GAP_F2);
    }

    private int processF4(ByteBuffer buffer) {
        byte[] FlexIP = new byte[32];
        buffer.get(FlexIP, 0, 32);
        long flexip = ((long)FlexIP[31] & 0xff) +
                        (((long)FlexIP[30] & 0xff) << 8) + 
                        (((long)FlexIP[29] & 0xff) << 16) + 
                        (((long)FlexIP[28] & 0xff) << 24) + 
                        (((long)FlexIP[27] & 0xff) << 32) + 
                        (((long)FlexIP[26] & 0xff) << 40);
        return calculateHost(flexip, 0L, FLEXIP_GAP_F4);
    }

    private int calculateHost(int flexip, int offset, int gap) {
        int vmx = (flexip - offset) / gap;
        int i = flexip - offset - vmx * gap + 64;
        return vmx * 255 + i;
    }

    private int calculateHost(long flexip, long offset, long gap) {
        long vmx = (flexip - offset) / gap;
        long i = flexip - offset - vmx * gap + 64L;
        return (int)(vmx * 255 + i);
    }

    public int transferSrcFlexIP2Host(ByteBuffer buffer, int format, int length){
        log.warn("transferSrcFlexIP2Host flexIPParam:{}", buffer);
        buffer.position(52 - length/8);
        int host = 0;
        switch (format) {
            case RESTRAINED:
                int vmx = 1;
                host =  vmx * 255 + (buffer.get() & 0xff);
                break;
            case EXTENDABLE:
                host = processExtendableFormat(buffer);
                break;
            case HIERARCHICAL:
                host = processHierarchicalFormat(buffer);
                break;
            default:
                break;
        }
        return host;
    }

    public int transferDstFlexIP2Host(ByteBuffer buffer, int format, int length) {
        buffer.position(100 - length/8);
        int host = 0;
        switch (format) {
            case RESTRAINED:
                int vmx = 1;
                host =  vmx * 100 + (buffer.get() & 0xff);
                break;
            case EXTENDABLE:
                host = processExtendableFormat(buffer);
                break;
            case HIERARCHICAL:
                host = processHierarchicalFormat(buffer);
                break;
            default:
                break;
        }
        return host;
    }

    public FlowRule applyFlexIPFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer) {
        int flexip_prefix = ((buffer.get(0) & 0xff) << 24 | (buffer.get(1) & 0xff) << 16 | (buffer.get(2) & 0xff) << 8 | (buffer.get(3) & 0xff));
        int srcFormat = flexip_prefix >> 26 & 0x3;
        int dstFormat = flexip_prefix >> 24 & 0x3;
        int srcLength = flexip_prefix >> 12 & 0x7ff;
        int dstLength = flexip_prefix & 0x7ff;
        log.warn("flexip_prefix:{}, srcLength:{}, dstLength:{}", flexip_prefix, srcLength, dstLength);
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId srcFormatFieldId = PiMatchFieldId.of("hdr.flexip.srcFormat");
        PiMatchFieldId dstFormatFieldId = PiMatchFieldId.of("hdr.flexip.dstFormat");
        PiMatchFieldId srcAddrFieldId = PiMatchFieldId.of("hdr.flexip.srcAddr");
        PiMatchFieldId dstAddrFieldId = PiMatchFieldId.of("hdr.flexip.dstAddr");
        
        byte[] srcAddr = new byte[srcLength/8];
        buffer.position(52-srcLength/8);
        for(int i=0;i<srcLength/8;i++) {
            srcAddr[i] = buffer.get();
        }
        log.warn("srcFlexIP:{}",srcAddr);
        
        byte[] dstAddr = new byte[dstLength/8];
        buffer.position(100-dstLength/8);
        for(int i=0;i<dstLength/8;i++) {
            dstAddr[i] = buffer.get();
        }
        log.warn("dstFlexIP:{}",dstAddr);
        
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, 0x3690)
            .matchExact(srcFormatFieldId, srcFormat)
            .matchExact(dstFormatFieldId, dstFormat)
            .matchExact(srcAddrFieldId, srcAddr)
            .matchExact(dstAddrFieldId, dstAddr)
            .build();
        TrafficSelector selector = DefaultTrafficSelector.builder()
            .add(criteria)
            .build();
        PiTableAction piTableAction = PiAction.builder()
            .withId(PiActionId.of("ingress.set_next_flexip_hop"))
            .withParameter(new PiActionParam(PiActionParamId.of("dst_port"), ImmutableByteSequence.copyFrom(port)))
            .build();                
        TrafficTreatment treatment = DefaultTrafficTreatment.builder()
            .piTableAction(piTableAction)
            .build();
        FlowRule flowRule = DefaultFlowRule.builder()
            .forDevice(deviceId)
            .forTable(P4InfoConstants.TABLEID_FLEXIP)
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