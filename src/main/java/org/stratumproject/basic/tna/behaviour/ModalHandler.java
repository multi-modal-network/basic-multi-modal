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
                int srcLength = flexip_prefix >> 12 & 0xfff;
                int dstLength = flexip_prefix & 0xfff;
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

    // 烽火tofino交换机端口设置
    // private static final int[] domain2TofinoPorts = {132,140,148,164};
    // private static final int[] domain4TofinoPorts = {132,140,164};
    // private static final int[] domain6TofinoPorts = {132,140,148,164};

    // 武大tofino交换机端口设置
    private static final int[] domain2TofinoPorts = {128,144,160,176};
    private static final int[] domain4TofinoPorts = {128,144,176};
    private static final int[] domain6TofinoPorts = {128,144,160,176};

    // tofino交换机deviceId
    private static final int domain2TofinoSwitch = 2000;
    private static final int domain4TofinoSwitch = 4000;
    private static final int domain6TofinoSwitch = 6000;    

    // 卫星BMv2交换机deviceId
    private static final int domain3SatelliteSwitch1 = 3100;
    private static final int domain3SatelliteSwitch1 = 3200;
    private static final int domain3SatelliteSwitch1 = 3300;
    // 卫星交换机转发端口
    private static final int[] domain3SatellitePorts = {1,2,3};

    private int getDomain(int vmx) {
        if (vmx >= 0 && vmx <= 2) {            // A区是domain1，包含vmx0\vmx1\vmx2
            return 1;
        } else if (vmx >= 3 && vmx <= 4) {     // B区是domain5，包含vmx3\vmx4
            return 5;
        } else {                               // C区是domain7，包含vmx5\vmx6\vmx7
            return 7;
        }
    }

    private int getGroup(int vmx) {
        if (vmx == 0 || vmx == 3 || vmx==5) {
            return 1;
        } else if (vmx == 1 || vmx == 4 || vmx == 6) {
            return 2;
        } else {
            return 3;
        }
    }

    public void executeAddFlow(String modalType, int srcHost, int dstHost, ByteBuffer buffer) {
        // 获取源目主机的vmx
        int srcVmx = srcHost / 256;
        int dstVmx = dstHost / 256;
        int srcDomain = getDomain(srcVmx);
        int dstDomain = getDomain(dstVmx);
        // 数据平面group内实际交换机都是s1-s255
        int srcSwitch = (srcHost-1) % 255 + 1;
        int dstSwitch = (dstHost-1) % 255 + 1;
        ArrayList<String> involvedSwitches = new ArrayList<>();
        if(srcVmx == dstVmx) {          // 同group
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
        } else if (srcDomain == dstDomain) {       // 同域异group
            // 源group源主机直接发至S1
            while(srcSwitch != 0) {
                postFlow(modalType, srcSwitch, srcVmx, up, buffer);
                involvedSwitches.add(String.format("%d-%d", srcVmx, srcSwitch));
                srcSwitch = (int) Math.floor(srcSwitch / 2);
            }
            // tofino交换机下发流表
            switch(srcDomain) {
                case 1:
                    postFlow(modalType, domain2TofinoSwitch, 0, domain2TofinoPorts[dstVmx % 3], buffer);
                    involvedSwitches.add(String.format("domain2-%d", domain2TofinoPorts[dstVmx % 3]));
                    break;
                case 5:
                    postFlow(modalType, domain4TofinoSwitch, 0, domain4TofinoPorts[dstVmx % 3], buffer);
                    involvedSwitches.add(String.format("domain4-%d", domain4TofinoPorts[dstVmx % 3]));
                    break;
                case 7:
                    postFlow(modalType, domain6TofinoSwitch, 0, domain6TofinoPorts[(dstVmx+1) % 3], buffer);
                    involvedSwitches.add(String.format("domain6-%d", domain6TofinoPorts[(dstVmx+1) % 3]));
                    break;
            }
            // 目的groupS1直接发至目的主机
            postFlow(modalType, dstSwitch, dstVmx, left, buffer);
            involvedSwitches.add(String.format("%d-%d", dstVmx, dstSwitch));
            while(dstSwitch != 1) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father * 2 == dstSwitch) {
                    postFlow(modalType, father, dstVmx, left, buffer);
                } else {
                    postFlow(modalType, father, dstVmx, right, buffer);
                }
                involvedSwitches.add(String.format("%d-%d", dstVmx, father));
                dstSwitch = (int) Math.floor(dstSwitch / 2);
            }
        } else {                // 异域
            // 源group源主机直接发至S1
            while(srcSwitch != 0) {
                postFlow(modalType, srcSwitch, srcVmx, up, buffer);
                involvedSwitches.add(String.format("%d-%d", srcVmx, srcSwitch));
                srcSwitch = (int) Math.floor(srcSwitch / 2);
            }
            // tofino交换机下发流表
            switch(srcDomain + dstDomain) {
                case 6:
                    if (srcDomain < dstDomain) {        // 1->5 (对应的tofino交换机在domain2和domain4)
                        // domain2的Tofino交换机
                        postFlow(modalType, domain2TofinoSwitch, 0, domain2TofinoPorts[3], buffer);
                        involvedSwitches.add(String.format("domain2-%d", domain2TofinoPorts[3]));
                        // 中间的卫星BMv2交换机 (三台都下发流表)
                        postFlow(modalType, domain3SatelliteSwitch1, 0, domain3SatellitePorts[1], buffer);
                        postFlow(modalType, domain3SatelliteSwitch2, 0, domain3SatellitePorts[1], buffer);
                        postFlow(modalType, domain3SatelliteSwitch3, 0, domain3SatellitePorts[1], buffer);
                        involvedSwitches.add(String.format("domain3-%d", domain3SatellitePorts[1]));
                        // domain4的Tofino交换机
                        postFlow(modalType, domain4TofinoSwitch, 0, domain4TofinoPorts[dstVmx % 3], buffer);
                        involvedSwitches.add(String.format("domain4-%d", domain4TofinoPorts[dstVmx % 3]));
                    } else {                            // 5->1
                        postFlow(modalType, domain4TofinoSwitch, 0, domain4TofinoPorts[2], buffer);
                        involvedSwitches.add(String.format("domain4-%d", domain4TofinoPorts[2]));
                        postFlow(modalType, domain3SatelliteSwitch1, 0, domain3SatellitePorts[0], buffer);
                        postFlow(modalType, domain3SatelliteSwitch2, 0, domain3SatellitePorts[0], buffer);
                        postFlow(modalType, domain3SatelliteSwitch3, 0, domain3SatellitePorts[0], buffer);
                        involvedSwitches.add(String.format("domain3-%d", domain3SatellitePorts[0]));
                        postFlow(modalType, domain2TofinoSwitch, 0, domain2TofinoPorts[dstVmx % 3], buffer);
                        involvedSwitches.add(String.format("domain2-%d", domain2TofinoPorts[dstVmx % 3]));
                    }
                    break;
                case 8:
                    if (srcDomain < dstDomain) {        // 1->7 (对应的tofino交换机在domain2和domain6)
                        postFlow(modalType, domain2TofinoSwitch, 0, domain2TofinoPorts[3], buffer);
                        involvedSwitches.add(String.format("domain2-%d", domain2TofinoPorts[3]));
                        postFlow(modalType, domain3SatelliteSwitch1, 0, domain3SatellitePorts[2], buffer);
                        postFlow(modalType, domain3SatelliteSwitch2, 0, domain3SatellitePorts[2], buffer);
                        postFlow(modalType, domain3SatelliteSwitch3, 0, domain3SatellitePorts[2], buffer);
                        involvedSwitches.add(String.format("domain3-%d", domain3SatellitePorts[2]));
                        postFlow(modalType, domain6TofinoSwitch, 0, domain6TofinoPorts[(dstVmx+1) % 3], buffer);
                        involvedSwitches.add(String.format("domain6-%d", domain6TofinoPorts[(dstVmx+1) % 3]));
                    } else {                            // 7->1
                        postFlow(modalType, domain6TofinoSwitch, 0, domain6TofinoPorts[3], buffer);
                        involvedSwitches.add(String.format("domain6-%d", domain4TofinoPorts[3]));
                        postFlow(modalType, domain3SatelliteSwitch1, 0, domain3SatellitePorts[0], buffer);
                        postFlow(modalType, domain3SatelliteSwitch2, 0, domain3SatellitePorts[0], buffer);
                        postFlow(modalType, domain3SatelliteSwitch3, 0, domain3SatellitePorts[0], buffer);
                        involvedSwitches.add(String.format("domain3-%d", domain3SatellitePorts[0]));
                        postFlow(modalType, domain2TofinoSwitch, 0, domain2TofinoPorts[dstVmx % 3], buffer);
                        involvedSwitches.add(String.format("domain2-%d", domain2TofinoPorts[dstVmx % 3]));
                    }
                    break;
                case 12:
                    if (srcDomain < dstDomain) {        // 5->7
                        postFlow(modalType, domain4TofinoSwitch, 0, domain4TofinoPorts[2], buffer);
                        involvedSwitches.add(String.format("domain4-%d", domain4TofinoPorts[2]));
                        postFlow(modalType, domain3SatelliteSwitch1, 0, domain3SatellitePorts[2], buffer);
                        postFlow(modalType, domain3SatelliteSwitch2, 0, domain3SatellitePorts[2], buffer);
                        postFlow(modalType, domain3SatelliteSwitch3, 0, domain3SatellitePorts[2], buffer);
                        involvedSwitches.add(String.format("domain3-%d", domain3SatellitePorts[2]));
                        postFlow(modalType, domain6TofinoSwitch, 0, domain6TofinoPorts[(dstVmx+1) % 3], buffer);
                        involvedSwitches.add(String.format("domain6-%d", domain6TofinoPorts[(dstVmx+1) % 3]));
                    } else {                            // 7->5
                        postFlow(modalType, domain6TofinoSwitch, 0, domain6TofinoPorts[3], buffer);
                        involvedSwitches.add(String.format("domain6-%d", domain6TofinoPorts[3]));
                        postFlow(modalType, domain3SatelliteSwitch1, 0, domain3SatellitePorts[1], buffer);
                        postFlow(modalType, domain3SatelliteSwitch2, 0, domain3SatellitePorts[1], buffer);
                        postFlow(modalType, domain3SatelliteSwitch3, 0, domain3SatellitePorts[1], buffer);
                        involvedSwitches.add(String.format("domain3-%d", domain3SatellitePorts[1]));
                        postFlow(modalType, domain4TofinoSwitch, 0, domain4TofinoPorts[dstVmx % 3], buffer);
                        involvedSwitches.add(String.format("domain4-%d", domain4TofinoPorts[dstVmx % 3]));
                    }
                    break;
            }
            // 目的groupS1直接发至目的主机
            postFlow(modalType, dstSwitch, dstVmx, left, buffer);
            involvedSwitches.add(String.format("%d-%d", dstVmx, dstSwitch));
            while(dstSwitch != 1) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father * 2 == dstSwitch) {
                    postFlow(modalType, father, dstVmx, left, buffer);
                } else {
                    postFlow(modalType, father, dstVmx, right, buffer);
                }
                involvedSwitches.add(String.format("%d-%d", dstVmx, father));
                dstSwitch = (int) Math.floor(dstSwitch / 2);
            }
        }
        log.warn("involvedSwitches:{}", involvedSwitches);
    }

    public void postFlow(String modalType, int switchID, int vmx, int port, ByteBuffer buffer) {
        DeviceId deviceId;
        if (switchID == domain2TofinoSwitch) {
            deviceId = DeviceId.deviceId(String.format("device:domain2:p1"));
        } else if (switchID == domain4TofinoSwitch) {
            deviceId = DeviceId.deviceId(String.format("device:domain4:p4"));
        } else if (switchID == domain6TofinoSwitch) {
            deviceId = DeviceId.deviceId(String.format("device:domain6:p6"));
        } else if (switchID == domain3SatelliteSwitch1) {
            deviceId = DeviceId.deviceId(String.format("device:satellite1"));
        } else if (switchID == domain3SatelliteSwitch2) {
            deviceId = DeviceId.deviceId(String.format("device:satellite2"));
        } else if (switchID == domain3SatelliteSwitch3) {
            deviceId = DeviceId.deviceId(String.format("device:satellite3"));
        } else {
            int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
            deviceId = DeviceId.deviceId(String.format("device:domain%d:group%d:level%d:s%d", getDomain(vmx), getGroup(vmx), level, switchID + 255 * vmx));
        }
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