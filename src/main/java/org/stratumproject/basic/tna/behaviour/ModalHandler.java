package org.stratumproject.basic.tna.behaviour;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.slf4j.Logger;

import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.slf4j.LoggerFactory.getLogger;


public class ModalHandler {
    private static final Logger log = getLogger(ModalHandler.class);

    private ApplicationId appId;
    private FlowRuleService flowRuleService;

    public ModalHandler(ApplicationId appId, FlowRuleService flowRuleService) {
        this.appId = appId;
        this.flowRuleService = flowRuleService;
    }

    public void handleModalPacket(int pktType, byte[] payload, DeviceId deviceId) {
        String modalType = "";
        int srcHost = 0, dstHost = 0;
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        log.warn("payload: {}, buffer: {}, deviceId: {}", payload, buffer, deviceId);
        switch(pktType){
            case 0x0800:    // IP
                modalType = "ipv4";
                srcHost = transferIP2Host(((buffer.get(14) & 0xff) << 8) + (buffer.get(15) & 0xff));
                dstHost = transferIP2Host(((buffer.get(18) & 0xff) << 8) + (buffer.get(19) & 0xff));
                break;
            case 0x0812:    // ID
                modalType = "id";
                srcHost = transferID2Host(buffer.getInt(0) & 0xffffffff);
                dstHost = transferID2Host(buffer.getInt(4) & 0xffffffff);
                break;
            case 0x8947:    // GEO
                modalType = "geo";
                String deviceIdStr = deviceId.toString();
                srcHost = Integer.parseInt(deviceIdStr.substring(deviceIdStr.length() - 3));
                dstHost = transferGEO2Host(buffer.getInt(40) & 0xffffffff);
                break;
            case 0x27c0:    // MF
                modalType = "mf";
                srcHost = transferMF2Host(buffer.getInt(4) & 0xffffffff);
                dstHost = transferMF2Host(buffer.getInt(8) & 0xffffffff);
                break;
            case 0x8624:    // NDN
                modalType = "ndn";
                srcHost = transferNDN2Host(buffer.getInt(8) & 0xffffffff);
                dstHost = transferNDN2Host(buffer.getInt(14) & 0xffffffff);
                break;
            case 0x3690:    // FLEXIP
                modalType = "flexip";
                int flexip_prefix = ((buffer.get(0) & 0xff) << 24 | (buffer.get(1) & 0xff) << 16 | (buffer.get(2) & 0xff) << 8 | (buffer.get(3) & 0xff));
                int srcFormat = flexip_prefix >> 26 & 0x3;
                int dstFormat = flexip_prefix >> 24 & 0x3;
                int srcLength = flexip_prefix >> 12 & 0x7ff;
                int dstLength = flexip_prefix & 0x7ff;
                srcHost = transferSrcFlexIP2Host(buffer, srcFormat, srcLength);
                dstHost = transferDstFlexIP2Host(buffer, dstFormat, dstLength);
                break;
        }
        if (modalType == "ipv4" || modalType == "id" || modalType == "geo" || modalType == "mf" || modalType == "ndn" || modalType == "flexip") {
            log.warn("modalType: {}, srcHost: {}, dstHost: {}", modalType, srcHost, dstHost);
            String path = "/home/onos/Desktop/ngsdn/mininet/flows.out";
            String content = modalType + " " + srcHost + " " + dstHost;
            try (FileOutputStream fos = new FileOutputStream(path, true)) {
                fos.write(System.lineSeparator().getBytes());
                fos.write(content.getBytes());
                log.info("message written to file... {}", content);
            } catch (IOException e) {
                e.printStackTrace();
            }
            executeAddFlow(modalType, srcHost, dstHost, buffer);
        }
    }

    public void executeAddFlow(String modalType, int srcHost, int dstHost, ByteBuffer buffer) {
        int srcSwitch = srcHost-100;   // h180-eth0 <-> s80-eth2
        int dstSwitch = dstHost-100;   // h166-eth0 <-> s66-eth2
        ArrayList<Integer> involvedSwitches = new ArrayList<>();

        // 交换机的eth0\eth1\eth2对应转发端口0\1\2
        // srcSwitch至lca(srcSwitch,dstSwitch)路径中交换机需要下发流表（当前节点向父节点转发）
        // lca(srcSwitch,dstSwitch)至dstSwitch路径中交换机需要下发流表（当前节点的父节点向当前节点转发）

        postFlow(modalType, dstSwitch, 2, srcHost, dstHost, buffer);   // dstSwitch需要向网卡eth2的端口转发
        involvedSwitches.add(dstSwitch);

        int srcDepth = (int) Math.floor(Math.log(srcSwitch)/Math.log(2)) + 1;
        int dstDepth = (int) Math.floor(Math.log(dstSwitch)/Math.log(2)) + 1;

        log.warn("srcHost:{}, dstHost:{}, srcSwitch:{}, dstSwitch:{}, srcDepth:{}, dstDepth:{}",
                srcHost, dstHost, srcSwitch, dstSwitch, srcDepth, dstDepth);

        // srcSwitch深度更大
        if (srcDepth > dstDepth) {
            while (srcDepth != dstDepth) {
                postFlow(modalType, srcSwitch, 1, srcHost, dstHost, buffer);  // 只能通过eth1向父节点转发
                involvedSwitches.add(srcSwitch);
                srcSwitch = (int) Math.floor(srcSwitch / 2);
                srcDepth = srcDepth - 1;
            } 
        }

        // dstSwitch深度更大
        if (srcDepth < dstDepth) {
            while (srcDepth != dstDepth) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father*2 == dstSwitch) {
                    postFlow(modalType, father, 2, srcHost, dstHost, buffer);    // 通过eth2向左儿子转发
                } else {
                    postFlow(modalType, father, 3, srcHost, dstHost, buffer);   // 通过eth3向右儿子转发
                }
                involvedSwitches.add(father);
                dstSwitch = (int) Math.floor(dstSwitch / 2);
                dstDepth = dstDepth - 1;
            }
        }

        // srcSwitch和dstSwitch在同一层，srcSwitch向父节点转发，dstSwitch的父节点向dstSwitch转发
        while(true){
            postFlow(modalType, srcSwitch, 1, srcHost, dstHost, buffer);
            int father = (int) Math.floor(dstSwitch / 2);
            if (father*2 == dstSwitch) {
                postFlow(modalType, father, 2, srcHost, dstHost, buffer);
            } else {
                postFlow(modalType, father, 3, srcHost, dstHost, buffer);
            }
            involvedSwitches.add(srcSwitch);
            involvedSwitches.add(father);
            srcSwitch = (int) Math.floor(srcSwitch / 2);
            dstSwitch = (int) Math.floor(dstSwitch / 2);
            if (srcSwitch == dstSwitch) {
                break;
            }
        }
        log.warn("involvedSwitches:{}", involvedSwitches);
    }

    public void postFlow(String modalType, int switchID, int port, int srcHost, int dstHost, ByteBuffer buffer) {
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        int vmx = 1;    // todo: vmx标记
        int srcId = srcHost - vmx * 100;
        int dstId = dstHost - vmx * 100; 
        DeviceId deviceId = DeviceId.deviceId(String.format("device:domain1:group4:level%d:s%d",level, switchID + vmx * 100));
        FlowRule flowRule;
        switch (modalType) {
            case "ipv4":
                flowRule = applyIPv4Flow(deviceId, appId, port, buffer);
                break;
            case "id":
                flowRule = applyIDFlow(deviceId, appId, port, buffer);
                break;
            case "geo":
                flowRule = applyGEOFlow(deviceId, appId, port, buffer);
                break;
            case "mf":
                flowRule = applyMFFlow(deviceId, appId, port, buffer);
                break;
            case "ndn":
                flowRule = applyNDNFlow(deviceId, appId, port, buffer);
                break;
            case "flexip":
                flowRule = applyFlexIPFlow(deviceId, appId, port, buffer);
                break;
            default:
                log.error("Invalid modal type: {}", modalType);
                throw new IllegalArgumentException("Invalid modal type: " + modalType); // Throw an exception if modalType is invalid
        }
        flowRuleService.applyFlowRules(flowRule);
        log.warn("{} flow rule applied! {}", modalType, flowRule);
    }
    
    // ---------------------IP模态---------------------
    private int transferIP2Host(int ipParam) {
        log.warn("transferIP2Host ipParam:{}", ipParam);
        int vmx = ((ipParam & 0xffff) >> 8) - 1;
        int i = (ipParam & 0xff) + 64 - 12;
        return vmx * 100 + i;
    }

    // ---------------------ID模态---------------------
    private int transferID2Host(int idParam) {
        log.warn("transferID2Host idParam:{}",idParam);
        int vmx = (idParam - 202271720) / 100000;
        int i = idParam - 202271720 - vmx * 100000 + 64;
        return vmx * 100 + i;
    }

    // ---------------------MF模态---------------------
    private int transferMF2Host(int mfParam) {
        log.warn("transferMF2Host mfParam:{}", mfParam);
        int vmx = (mfParam - 1) / 100;
        int i = mfParam - 1 - vmx * 100 + 64;
        return vmx * 100 + i;
    }

    // ---------------------NDN模态---------------------
    private int transferNDN2Host(int param) {
        log.warn("transferNDN2Host param:{}", param);
        int vmx = (param - 202271720) / 100000;
        int i = param - 202271720 - vmx * 100000 + 64;
        return vmx * 100 + i;
    }

    // ---------------------GEO模态---------------------
    private int transferGEO2Host(int geoParam) {
        log.warn("transferGEO2Host geoParam:{}", geoParam);
        // todo： 获取vmx
        int vmx = 1;
        return vmx * 100 + geoParam + 63;
    }

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
        return vmx * 100 + i;
    }

    private int calculateHost(long flexip, long offset, long gap) {
        long vmx = (flexip - offset) / gap;
        long i = flexip - offset - vmx * gap + 64L;
        return (int)(vmx * 100 + i);
    }

    private int transferSrcFlexIP2Host(ByteBuffer buffer, int format, int length){
        log.warn("transferSrcFlexIP2Host flexIPParam:{}", buffer);
        buffer.position(52 - length/8);
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

    private int transferDstFlexIP2Host(ByteBuffer buffer, int format, int length) {
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

    // ------------------------------------------ applyFlow ------------------------------------------
    private FlowRule applyIPv4Flow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer) {
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

    private FlowRule applyIDFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId srcIdentityFieldId = PiMatchFieldId.of("hdr.id.srcIdentity");
        PiMatchFieldId dstIdentityFieldId = PiMatchFieldId.of("hdr.id.dstIdentity");

        byte[] srcIdentity = new byte[4];
        buffer.position(0);
        for(int i=0;i<4;i++) {
            srcIdentity[i] = buffer.get();
        }

        byte[] dstIdentity = new byte[4];
        buffer.position(4);
        for(int i=0;i<4;i++) {
            srcIdentity[i] = buffer.get();
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

    private FlowRule applyGEOFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId geoAreaPosLatFieldId = PiMatchFieldId.of("hdr.gbc.geoAreaPosLat");
        PiMatchFieldId geoAreaPosLonFieldId = PiMatchFieldId.of("hdr.gbc.geoAreaPosLon");
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

    private FlowRule applyMFFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        PiMatchFieldId srcGuidFieldId = PiMatchFieldId.of("hdr.mf.src_guid");
        PiMatchFieldId dstGuidFieldId = PiMatchFieldId.of("hdr.mf.dest_guid");
        
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

    private FlowRule applyNDNFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer) {
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

    private FlowRule applyFlexIPFlow(DeviceId deviceId, ApplicationId appId, int port, ByteBuffer buffer) {
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