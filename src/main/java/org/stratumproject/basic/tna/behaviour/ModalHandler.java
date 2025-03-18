package org.stratumproject.basic.tna.behaviour;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;

import org.json.JSONObject;
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
import java.sql.*;
import java.util.Base64;
import org.json.JSONArray;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;

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

    public void handleModalPacket(int pktType, byte[] payload, DeviceId deviceId) throws Exception{
        String modalType = "";
        int srcHost = 0, dstHost = 0;
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        log.warn("payload: {}, buffer: {}, deviceId: {}", payload, buffer, deviceId);
        switch(pktType){
            case 0x0800:    // IP
                if((buffer.get(12) & 0xff) == 0xac && (buffer.get(13) & 0xff) == 0x14 && (buffer.get(16) & 0xff) == 0xac && (buffer.get(17) & 0xff) == 0x14){
                    modalType = "ipv4";
                    srcHost = ipv4.transferIP2Host(((buffer.get(14) & 0xff) << 8) + (buffer.get(15) & 0xff));
                    dstHost = ipv4.transferIP2Host(((buffer.get(18) & 0xff) << 8) + (buffer.get(19) & 0xff));
                }
                break;
            case 0x0812:    // ID
                modalType = "id";
                srcHost = id.transferID2Host(buffer.getInt(0) & 0xffffffff);
                dstHost = id.transferID2Host(buffer.getInt(4) & 0xffffffff);
                break;
            case 0x8947:    // GEO
                modalType = "geo";
                String deviceIdStr = deviceId.toString();
                srcHost = Integer.parseInt(deviceIdStr.substring(30));      // 源主机号就是对应的deviceID的switch号（注意switchID长度）
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
            String path = "/flows.out";
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
    private static final int[] domain2TofinoPorts = {132,140,148,164};
    private static final int[] domain4TofinoPorts = {132,140,164};
    private static final int[] domain6TofinoPorts = {132,140,148,164};

    // 武大tofino交换机端口设置
    // private static final int[] domain2TofinoPorts = {128,144,160,176};
    // private static final int[] domain4TofinoPorts = {128,144,176};
    // private static final int[] domain6TofinoPorts = {128,144,160,176};

    // tofino交换机deviceId
    private static final int domain2TofinoSwitch = 2000;
    private static final int domain4TofinoSwitch = 4000;
    private static final int domain6TofinoSwitch = 6000;    

    // 卫星BMv2交换机deviceId
    private static final int domain3SatelliteSwitch1 = 3100;
    private static final int domain3SatelliteSwitch2 = 3200;
    private static final int domain3SatelliteSwitch3 = 3300;
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

    public void executeAddFlow(String modalType, int srcHost, int dstHost, ByteBuffer buffer) throws Exception {
        // 获取源目主机的vmx
        int srcVmx = srcHost / 256;
        int dstVmx = dstHost / 256;
        int srcDomain = getDomain(srcVmx);
        int dstDomain = getDomain(dstVmx);
        // 数据平面group内实际交换机都是s1-s255
        int srcSwitch = (srcHost-1) % 255 + 1;
        int dstSwitch = (dstHost-1) % 255 + 1;
        ArrayList<String> involvedSwitches = new ArrayList<>();

        // 发送给go程序带有deviceID的数组
        ArrayList<String> sendArray = new ArrayList<>();

        if(srcVmx == dstVmx) {          // 同group
            int commonVmx = srcVmx;
            // 交换机的eth0\eth1\eth2对应转发端口0\1\2
            // srcSwitch至lca(srcSwitch,dstSwitch)路径中交换机需要下发流表（当前节点向父节点转发）
            // lca(srcSwitch,dstSwitch)至dstSwitch路径中交换机需要下发流表（当前节点的父节点向当前节点转发）
            postFlow(modalType, dstSwitch, commonVmx, left, buffer);   // dstSwitch需要向网卡eth2的端口转发

            int sendlevel = (int) (Math.log(dstSwitch)/Math.log(2)) + 1;
            sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(commonVmx), getGroup(commonVmx), sendlevel, dstSwitch + 255 * commonVmx));
            // 数据平面group内实际交换机都是s1-s255,所以这里还是加一步SwitchID + 255 * commonVmx

            involvedSwitches.add(String.format("t%d-s%d", commonVmx+1, dstSwitch));
            int srcDepth = (int) Math.floor(Math.log(srcSwitch)/Math.log(2)) + 1;
            int dstDepth = (int) Math.floor(Math.log(dstSwitch)/Math.log(2)) + 1;
            log.warn("srcHost:{}, dstHost:{}, srcSwitch:{}, dstSwitch:{}, srcDepth:{}, dstDepth:{}",
                    srcHost, dstHost, srcSwitch, dstSwitch, srcDepth, dstDepth);
            // srcSwitch深度更大
            if (srcDepth > dstDepth) {
                while (srcDepth != dstDepth) {
                    postFlow(modalType, srcSwitch, commonVmx, up, buffer);  // 只能通过eth1向父节点转发

                    int level = (int) (Math.log(dstSwitch)/Math.log(2)) + 1;
                    sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(commonVmx), getGroup(commonVmx), level, srcSwitch + 255 * commonVmx));

                    involvedSwitches.add(String.format("t%d-s%d", commonVmx+1, srcSwitch));
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

                    int level = (int) (Math.log(father)/Math.log(2)) + 1;
                    sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(commonVmx), getGroup(commonVmx), level, father + 255 * commonVmx));

                    involvedSwitches.add(String.format("t%d-s%d", commonVmx+1, father));
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

                int level = (int) (Math.log(srcSwitch)/Math.log(2)) + 1;
                sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(commonVmx), getGroup(commonVmx), level, srcSwitch + 255 * commonVmx));

                level = (int) (Math.log(father)/Math.log(2)) + 1;
                sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(commonVmx), getGroup(commonVmx), level, father + 255 * commonVmx));

                involvedSwitches.add(String.format("t%d-s%d", commonVmx+1, srcSwitch));
                involvedSwitches.add(String.format("t%d-s%d", commonVmx+1, father));
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

                int level = (int) (Math.log(srcSwitch)/Math.log(2)) + 1;
                sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(srcVmx), getGroup(srcVmx), level, srcSwitch + 255 * srcVmx));

                involvedSwitches.add(String.format("t%d-s%d", srcVmx+1, srcSwitch));
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

            int level = (int) (Math.log(dstSwitch)/Math.log(2)) + 1;
            sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(dstVmx), getGroup(dstVmx), level, dstSwitch + 255 * dstVmx));

            involvedSwitches.add(String.format("t%d-s%d", dstVmx+1, dstSwitch));
            while(dstSwitch != 1) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father * 2 == dstSwitch) {
                    postFlow(modalType, father, dstVmx, left, buffer);
                } else {
                    postFlow(modalType, father, dstVmx, right, buffer);
                }

                int sendlevel = (int) (Math.log(father)/Math.log(2)) + 1;
                sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(dstVmx), getGroup(dstVmx), sendlevel, father + 255 * dstVmx));

                involvedSwitches.add(String.format("t%d-s%d", dstVmx+1, father));
                dstSwitch = (int) Math.floor(dstSwitch / 2);
            }
        } else {                // 异域
            // 源group源主机直接发至S1
            while(srcSwitch != 0) {
                postFlow(modalType, srcSwitch, srcVmx, up, buffer);

                int sendlevel = (int) (Math.log(srcSwitch)/Math.log(2)) + 1;
                sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(srcVmx), getGroup(srcVmx), sendlevel, srcSwitch + 255 * srcVmx));

                involvedSwitches.add(String.format("t%d-s%d", srcVmx+1, srcSwitch));
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
                        involvedSwitches.add(String.format("domain6-%d", domain6TofinoPorts[3]));
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

            int sendlevel = (int) (Math.log(dstSwitch)/Math.log(2)) + 1;
            sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(dstVmx), getGroup(dstVmx), sendlevel, dstSwitch + 255 * dstVmx));

            involvedSwitches.add(String.format("t%d-s%d", dstVmx+1, dstSwitch));
            while(dstSwitch != 1) {
                int father = (int) Math.floor(dstSwitch / 2);
                if (father * 2 == dstSwitch) {
                    postFlow(modalType, father, dstVmx, left, buffer);
                } else {
                    postFlow(modalType, father, dstVmx, right, buffer);
                }

                int level = (int) (Math.log(father)/Math.log(2)) + 1;
                sendArray.add(String.format("device:domain%d:group%d:level%d:s%d", getDomain(dstVmx), getGroup(dstVmx), level, father + 255 * dstVmx));

                involvedSwitches.add(String.format("t%d-s%d", dstVmx+1, father));
                dstSwitch = (int) Math.floor(dstSwitch / 2);
            }
        }

        String IP = "218.199.84.172";
        // String APP_ID = "org.stratumproject.basic-tna";  // 这个app_id决定go的接口是什么
        String urlString = String.format("http://%s:8188/api/checkpipe", IP);
        String auth = "onos:rocks";//
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());


//        // 将ArrayList中的元素用逗号拼接成字符串
//        StringBuilder stringBuilder = new StringBuilder();
//        for (String s : involvedSwitches) {
//            if (stringBuilder.length() > 0) {
//                stringBuilder.append(",");
//            }
//            stringBuilder.append(s);
//        }
//        String listAsString = stringBuilder.toString();
//        urlString = urlString + "&list=" + listAsString;

        // 生成请求的json数据
        JSONObject jsonData = new JSONObject();;
        // 将 ArrayList 转换为 JSON 数组
        JSONArray jsonArray = new JSONArray(sendArray);
        // 将 JSONArray 添加到 jsonData 对象中
        jsonData.put("sendArray", jsonArray);

        jsonData.put("modalType", modalType);

        // 发送请求
        try {
            log.warn("------------data------------\n");
            // 创建一个HTTP POST请求
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            // connection.setRequestMethod("GET");

            // 设置 HTTP 请求头的属性
            // 例如 Content-Type 属性设置成 application/json，告知服务器客户端发送的数据类型是 JSON 格式。
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "Basic " + encodedAuth);  // HTTP 的认证格式
            connection.setDoOutput(true);  // 允许向服务器输出数据

            // 发送JSON数据
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonData.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // 获取服务器的响应码 responseCode，如果响应码为 HTTP_OK（200）
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                log.warn("Success: " + connection.getResponseMessage());

                // 读取响应内容
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                    StringBuilder response = new StringBuilder();  //  处理可变的字符串

                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }

                    // 解析 JSON 响应
                    try {
                        JSONObject jsonResponse = new JSONObject(response.toString());
                        // 获得不支持该模态的主机列表
                        if (jsonResponse.has("unsupported")) {
                            JSONArray dataArray = jsonResponse.getJSONArray("unsupported");

                            // 打印 unsupported 数组内容到日志
                            for (int i = 0; i < dataArray.length(); i++) {
                                log.warn("不支持该模态的主机为 {}: {}", i, dataArray.get(i));
                            }
                        } else {
                            log.warn("返回的 json 文件不包含 'unsupported' 数组.");
                        }
                    } catch (Exception e) {
                        log.error("Error parsing JSON response: ", e);
                    }
                }
            }
            else {
                log.warn("Status Code: " + responseCode);
                log.warn("Response Body: " + connection.getResponseMessage());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

//        ArrayList<Boolean> isContain = new ArrayList<>();
//        for (int i = 0; i < isContain.size(); i++) {
//            if(isContain.get(i) == false){
//                log.warn("不包含该模态");
//            }
//        }

        log.warn("involvedSwitches:{}", involvedSwitches);
    }

    public void postFlow(String modalType, int switchID, int vmx, int port, ByteBuffer buffer) {
        DeviceId deviceId;
        //String deviceIdStr;
        if (switchID == domain2TofinoSwitch) {
            deviceId = DeviceId.deviceId(String.format("device:domain2:p1"));
            //deviceIdStr = String.format("device:domain2:p1");
        } else if (switchID == domain4TofinoSwitch) {
            deviceId = DeviceId.deviceId(String.format("device:domain4:p4"));
            //deviceIdStr = String.format("device:domain4:p4");
        } else if (switchID == domain6TofinoSwitch) {
            deviceId = DeviceId.deviceId(String.format("device:domain6:p6"));
            //deviceIdStr = String.format("device:domain6:p6");
        } else if (switchID == domain3SatelliteSwitch1) {
            deviceId = DeviceId.deviceId(String.format("device:satellite1"));
            //deviceIdStr = String.format("device:satellite1");
        } else if (switchID == domain3SatelliteSwitch2) {
            deviceId = DeviceId.deviceId(String.format("device:satellite2"));
            //deviceIdStr = String.format("device:satellite2");
        } else if (switchID == domain3SatelliteSwitch3) {
            deviceId = DeviceId.deviceId(String.format("device:satellite3"));
            //deviceIdStr = String.format("device:satellite3");
        } else {
            int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
            deviceId = DeviceId.deviceId(String.format("device:domain%d:group%d:level%d:s%d", getDomain(vmx), getGroup(vmx), level, switchID + 255 * vmx));
            //deviceIdStr = String.format("device:domain%d:group%d:level%d:s%d", getDomain(vmx), getGroup(vmx), level, switchID + 255 * vmx);
        }
//        String url  = "jdbc:mysql://localhost:3306/devices?";
//        String user = "root";
//        String password = "root";
//        String sql = "SELECT support_modal FROM devices WHERE device_id = ?";
//        try{
//            Class.forName("com.mysql.cj.jdbc.Driver");
//        }catch(ClassNotFoundException e) {
//            System.out.println("未找到 MySQL JDBC 驱动！");
//            e.printStackTrace();
//        }
//        try (Connection conn = DriverManager.getConnection(url, user, password);
//             PreparedStatement pstmt = conn.prepareStatement(sql)) {
//            pstmt.setString(1, deviceIdStr);
//            try (ResultSet rs = pstmt.executeQuery()) {
//                if (rs.next()) {
//                    String supportModal = rs.getString("support_modal");
//                    if (supportModal == null || !supportModal.contains(modalType)) {
//                        String message = String.format(
//                            "Device ID: %s does not support modal type: %s\n",
//                            deviceIdStr, modalType
//                        );
//                        String path = "/unsurpported.out";
//                        try (FileOutputStream fos = new FileOutputStream(path, true)) {
//                                fos.write(message.getBytes());
//                                log.info("message written to file... {}", message);
//                        } catch (IOException e) {
//                            e.printStackTrace();
//                        }
//                    }
//                }
//            }
//        } catch (SQLException e) {
//            e.printStackTrace();
//        }
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