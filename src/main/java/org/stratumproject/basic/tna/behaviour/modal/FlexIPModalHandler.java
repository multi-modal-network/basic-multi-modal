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
    private static final int FLEXIP_GAP_F0 = 255;
    private static final int FLEXIP_GAP_F1 = 255*255;
    private static final int FLEXIP_GAP_F2 = 255*255*255;
    private static final long FLEXIP_GAP_F4 = 255*255*255*255L;

    private static final int RESTRAINED = 0;
    private static final int EXTENDABLE = 1;
    private static final int HIERARCHICAL = 2;
    private static final int MULTISEMANTICS = 3;

    private int processRestrainedFormat(ByteBuffer buffer) {
        int value = buffer.get() & 0xff;
        int vmx = value / 20;
        int hostId = value - vmx * 20 + 128;
        return vmx * 255 + hostId;
    }

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
                int value = afterByte & 0xff;
                int vmx = value / 20;
                int hostId = value - vmx * 20 + 128;
                host = vmx * 255 + hostId;
                break;
        }
        return host;
    }

    private int processF0(ByteBuffer buffer) {
        byte[] FlexIP = new byte[2];
        buffer.get(FlexIP, 0, 2);
        int flexip = ((FlexIP[0] & 0xff) << 8) + (FlexIP[1] & 0xff);
        return calculateHost(flexip, FLEXIP_GAP_F0);
    }

    private int processF1(ByteBuffer buffer) {
        byte[] FlexIP = new byte[4];
        buffer.get(FlexIP, 0, 4);
        int flexip = ((FlexIP[0] & 0xff) << 24) + 
                     ((FlexIP[1] & 0xff) << 16) + 
                     ((FlexIP[2] & 0xff) << 8) + 
                     (FlexIP[3] & 0xff);
        return calculateHost(flexip, FLEXIP_GAP_F1);
    }

    private int processF2(ByteBuffer buffer) {
        byte[] FlexIP = new byte[8];
        buffer.get(FlexIP, 0, 8);
        long flexip = (((long)FlexIP[4] & 0xff) << 24) + 
                        (((long)FlexIP[5] & 0xff) << 16) + 
                        (((long)FlexIP[6] & 0xff) << 8) + 
                        ((long)FlexIP[7] & 0xff);
        return calculateHost(flexip, FLEXIP_GAP_F2);
    }

    private int processF4(ByteBuffer buffer) {
        byte[] FlexIP = new byte[32];
        buffer.get(FlexIP, 0, 32);
        long flexip = ((long)FlexIP[31] & 0xff) +
                        (((long)FlexIP[30] & 0xff) << 8) + 
                        (((long)FlexIP[29] & 0xff) << 16) + 
                        (((long)FlexIP[28] & 0xff) << 24);
        return calculateHost(flexip, FLEXIP_GAP_F4);
    }

    private int calculateHost(int flexip, int gap) {
        int vmx = flexip / gap;
        int i = flexip - vmx * gap;
        return vmx * 255 + i;
    }

    private int calculateHost(long flexip, long gap) {
        long vmx = flexip / gap;
        long i = flexip - vmx * gap;
        return (int)(vmx * 255 + i);
    }

    public int transferSrcFlexIP2Host(ByteBuffer buffer, int format, int length){
        log.warn("transferSrcFlexIP2Host flexIPParam:{}", buffer);
        buffer.position(52 - length/8);
        int host = 0;
        switch (format) {
            case RESTRAINED:
                host = processRestrainedFormat(buffer);
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
        log.warn("transferDstFlexIP2Host flexIPParam:{}", buffer);
        buffer.position(100 - length/8);
        int host = 0;
        switch (format) {
            case RESTRAINED:
                host = processRestrainedFormat(buffer);
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
        PiMatchFieldId srcFormatFieldId = PiMatchFieldId.of("hdr.flexip.src_format");
        PiMatchFieldId dstFormatFieldId = PiMatchFieldId.of("hdr.flexip.dst_format");
        PiMatchFieldId srcAddrFieldId = PiMatchFieldId.of("hdr.flexip.src_addr");
        PiMatchFieldId dstAddrFieldId = PiMatchFieldId.of("hdr.flexip.dst_addr");
        
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