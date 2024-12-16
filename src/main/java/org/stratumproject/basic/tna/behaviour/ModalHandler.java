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
    private IPv4ModalHandler ipv4;
    private FlexIPModalHandler flexip;
    private GEOModalHandler geo;
    private IDModalHandler id;
    private MFModalHandler mf;
    private NDNModalHandler ndn;

    public ModalHandler(ApplicationId appId, FlowRuleService flowRuleService) {
        this.appId = appId;
        this.flowRuleService = flowRuleService;
        this.ipv4 = new IPv4ModalHandler();
        this.flexip = new FlexIPModalHandler();
        this.geo = new GEOModalHandler();
        this.id = new IDModalHandler();
        this.ndn = new NDNModalHandler();
        this.mf = new MFModalHandler();
    }

    public void handleModalPacket(int pktType, byte[] payload, DeviceId deviceId) {
        String modalType = "";
        int srcHost = 0, dstHost = 0;
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        log.warn("payload: {}, buffer: {}, deviceId: {}", payload, buffer, deviceId);
        switch(pktType){
            case 0x0800:    // IP
                modalType = "ipv4";
                srcHost = ipv4.transferIP2Host(((buffer.get(14) & 0xff) << 8) + (buffer.get(15) & 0xff));
                dstHost = ipv4.transferIP2Host(((buffer.get(18) & 0xff) << 8) + (buffer.get(19) & 0xff));
                break;
            case 0x0812:    // ID
                modalType = "id";
                srcHost = id.transferID2Host(buffer.getInt(0) & 0xffffffff);
                dstHost = id.transferID2Host(buffer.getInt(4) & 0xffffffff);
                break;
            case 0x8947:    // GEO
                modalType = "geo";
                String deviceIdStr = deviceId.toString();
                int srcVmx = Character.getNumericValue(deviceIdStr.charAt(20));
                int srcId = Integer.parseInt(deviceIdStr.substring(30));
                srcHost = (srcVmx-1) * 255 + srcId;
                dstHost = geo.transferGEO2Host(buffer.getInt(40) & 0xffffffff, buffer.getInt(44) & 0xffffffff);
                break;
            case 0x27c0:    // MF
                modalType = "mf";
                srcHost = mf.transferMF2Host(buffer.getInt(4) & 0xffffffff);
                dstHost = mf.transferMF2Host(buffer.getInt(8) & 0xffffffff);
                break;
            case 0x8624:    // NDN
                modalType = "ndn";
                srcHost = ndn.transferNDN2Host(buffer.getInt(8) & 0xffffffff);
                dstHost = ndn.transferNDN2Host(buffer.getInt(14) & 0xffffffff);
                break;
            case 0x3690:    // FLEXIP
                modalType = "flexip";
                int flexip_prefix = ((buffer.get(0) & 0xff) << 24 | (buffer.get(1) & 0xff) << 16 | (buffer.get(2) & 0xff) << 8 | (buffer.get(3) & 0xff));
                int srcFormat = flexip_prefix >> 26 & 0x3;
                int dstFormat = flexip_prefix >> 24 & 0x3;
                int srcLength = flexip_prefix >> 12 & 0x7ff;
                int dstLength = flexip_prefix & 0x7ff;
                srcHost = flexip.transferSrcFlexIP2Host(buffer, srcFormat, srcLength);
                dstHost = flexip.transferDstFlexIP2Host(buffer, dstFormat, dstLength);
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

    // 拓扑上link的方向
    private static final int left = 2;
    private static final int right = 3;
    private static final int up = 1;

    public void executeAddFlow(String modalType, int srcHost, int dstHost, ByteBuffer buffer) {
        // 获取源目主机的vmx
        int srcVmx = srcHost / 256;
        int dstVmx = dstHost / 256;
        // 数据平面group内实际交换机都是s1-s255
        int srcSwitch = (srcHost-1) % 255 + 1;
        int dstSwitch = (dstHost-1) % 255 + 1;
        ArrayList<String> involvedSwitches = new ArrayList<>();
        // 如果源目主机在一个group内
        if(srcVmx == dstVmx) {
            int commonVmx = srcVmx;
            // 交换机的eth0\eth1\eth2对应转发端口0\1\2
            // srcSwitch至lca(srcSwitch,dstSwitch)路径中交换机需要下发流表（当前节点向父节点转发）
            // lca(srcSwitch,dstSwitch)至dstSwitch路径中交换机需要下发流表（当前节点的父节点向当前节点转发）
            postFlow(modalType, dstSwitch, commonVmx, left, buffer);   // dstSwitch需要向网卡eth2的端口转发
            involvedSwitches.add(String.format("%d-%d", commonVmx, dstSwitch));
            int srcDepth = (int) Math.floor(Math.log(srcSwitch)/Math.log(2)) + 1;
            int dstDepth = (int) Math.floor(Math.log(dstSwitch)/Math.log(2)) + 1;
            log.warn("srcHost:{}, dstHost:{}, srcSwitch:{}, dstSwitch:{}, srcDepth:{}, dstDepth:{}",
                    srcHost, dstHost, srcSwitch, dstSwitch, srcDepth, dstDepth);
            // srcSwitch深度更大
            if (srcDepth > dstDepth) {
                while (srcDepth != dstDepth) {
                    postFlow(modalType, srcSwitch, commonVmx, up, buffer);  // 只能通过eth1向父节点转发
                    involvedSwitches.add(String.format("%d-%d", commonVmx, srcSwitch));
                    srcSwitch = (int) Math.floor(srcSwitch / 2);
                    srcDepth = srcDepth - 1;
                } 
            }
            // dstSwitch深度更大
            if (srcDepth < dstDepth) {
                while (srcDepth != dstDepth) {
                    int father = (int) Math.floor(dstSwitch / 2);
                    if (father*2 == dstSwitch) {
                        postFlow(modalType, father, commonVmx, left, buffer);    // 通过eth2向左儿子转发
                    } else {
                        postFlow(modalType, father, commonVmx, right, buffer);   // 通过eth3向右儿子转发
                    }
                    involvedSwitches.add(String.format("%d-%d", commonVmx, father));
                    dstSwitch = (int) Math.floor(dstSwitch / 2);
                    dstDepth = dstDepth - 1;
                }
            }
            // srcSwitch和dstSwitch在同一层，srcSwitch向父节点转发，dstSwitch的父节点向dstSwitch转发
            while(true){
                postFlow(modalType, srcSwitch, commonVmx, 1, buffer);
                int father = (int) Math.floor(dstSwitch / 2);
                if (father*2 == dstSwitch) {
                    postFlow(modalType, father, commonVmx, left, buffer);
                } else {
                    postFlow(modalType, father, commonVmx, right, buffer);
                }
                involvedSwitches.add(String.format("%d-%d", commonVmx, srcSwitch));
                involvedSwitches.add(String.format("%d-%d", commonVmx, father));
                srcSwitch = (int) Math.floor(srcSwitch / 2);
                dstSwitch = (int) Math.floor(dstSwitch / 2);
                if (srcSwitch == dstSwitch) {
                    break;
                }
            }
        } else {       // 跨域
            // 源域源主机直接发至S1
            while(srcSwitch != 0) {
                postFlow(modalType, srcSwitch, srcVmx, up, buffer);
                involvedSwitches.add(String.format("%d-%d", srcVmx, srcSwitch));
                srcSwitch = (int) Math.floor(srcSwitch / 2);
            }
            // 目的域S1直接发至目的主机
            postFlow(modalType, dstSwitch, dstVmx, left, buffer);
            involvedSwitches.add(String.format("%d-%d", dstVmx, dstSwitch));
            while(true) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father * 2 == dstSwitch) {
                    postFlow(modalType, father, dstVmx, left, buffer);
                } else {
                    postFlow(modalType, father, dstVmx, right, buffer);
                }
                involvedSwitches.add(String.format("%d-%d", dstVmx, father));
                dstSwitch = (int) Math.floor(dstSwitch / 2);
                if (dstSwitch == 0) {
                    break;
                } 
            }
        }
        log.warn("involvedSwitches:{}", involvedSwitches);
    }

    public void postFlow(String modalType, int switchID, int vmx, int port, ByteBuffer buffer) {
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        DeviceId deviceId = DeviceId.deviceId(String.format("device:domain1:group%d:level%d:s%d", vmx + 1, level, switchID));
        FlowRule flowRule;
        switch (modalType) {
            case "ipv4":
                flowRule = ipv4.applyIPv4Flow(deviceId, appId, port, buffer);
                break;
            case "id":
                flowRule = id.applyIDFlow(deviceId, appId, port, buffer);
                break;
            case "geo":
                flowRule = geo.applyGEOFlow(deviceId, appId, port, buffer);
                break;
            case "mf":
                flowRule = mf.applyMFFlow(deviceId, appId, port, buffer);
                break;
            case "ndn":
                flowRule = ndn.applyNDNFlow(deviceId, appId, port, buffer);
                break;
            case "flexip":
                flowRule = flexip.applyFlexIPFlow(deviceId, appId, port, buffer);
                break;
            default:
                log.error("Invalid modal type: {}", modalType);
                throw new IllegalArgumentException("Invalid modal type: " + modalType); // Throw an exception if modalType is invalid
        }
        flowRuleService.applyFlowRules(flowRule);
        log.warn("{} flow rule applied! {}", modalType, flowRule);
    }
}