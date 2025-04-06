package org.stratumproject.basic.tna.behaviour;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

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
    private org.stratumproject.basic.tna.behaviour.IPv4ModalHandler ipv4;
    private org.stratumproject.basic.tna.behaviour.FlexIPModalHandler flexip;
    private org.stratumproject.basic.tna.behaviour.GEOModalHandler geo;
    private org.stratumproject.basic.tna.behaviour.IDModalHandler id;
    private org.stratumproject.basic.tna.behaviour.MFModalHandler mf;
    private org.stratumproject.basic.tna.behaviour.NDNModalHandler ndn;

    public ModalHandler(ApplicationId appId, FlowRuleService flowRuleService) {
        this.appId = appId;
        this.flowRuleService = flowRuleService;
        this.ipv4 = new org.stratumproject.basic.tna.behaviour.IPv4ModalHandler();
        this.flexip = new org.stratumproject.basic.tna.behaviour.FlexIPModalHandler();
        this.geo = new org.stratumproject.basic.tna.behaviour.GEOModalHandler();
        this.id = new org.stratumproject.basic.tna.behaviour.IDModalHandler();
        this.ndn = new org.stratumproject.basic.tna.behaviour.NDNModalHandler();
        this.mf = new org.stratumproject.basic.tna.behaviour.MFModalHandler();
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

    private JSONObject utilityResponse(String urlString, JSONObject jsonData, String method) {
        String auth = "onos:rocks";
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

        log.warn("------------sending request------------\n");

        JSONObject response = new JSONObject();
        // 创建一个HTTP请求
        try {
            HttpURLConnection connection;
            connection = (HttpURLConnection) new URL(urlString).openConnection();
            connection.setRequestMethod(method);
            connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
            if (method.equals("POST")) {    // POST请求
                connection.setDoOutput(true);
                connection.setRequestProperty("Authorization", "Basic "+encodedAuth);
                try (OutputStream os = connection.getOutputStream()) {
                    byte[] input = jsonData.toString().getBytes("UTF-8");
                    os.write(input,0,input.length);
                }
            }

            // 获取服务器的响应码 responseCode，如果响应码为 HTTP_OK（200）
            int responseCode = connection.getResponseCode();
            String responseMessage = connection.getResponseMessage();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // 读取响应内容
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder responseBuilder = new StringBuilder();  //  处理可变的字符串
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBuilder.append(line);
                }
                JSONObject responseData = new JSONObject(responseBuilder.toString());
                response.put("code", responseCode);
                response.put("message", responseMessage);
                response.put("data", responseData);
                log.warn("onosutil response success, code:{}, message:{}, data:{}", responseCode, responseMessage, responseData);
            } else {
                response.put("code", responseCode);
                response.put("message", responseMessage);
                log.warn("onosutil response success, code:{}, message:{}", responseCode, responseMessage);
            }
        } catch (IOException e) {
            // 处理 IO 异常
            log.error("IOException occurred: {}", e.getMessage());
            response.put("code", 500);
            response.put("message", "Internal Server Error");
        } catch (Exception e) {
            // 处理其他异常（如 JSONException）
            log.error("Exception occurred: {}", e.getMessage());
            response.put("code", 500);
            response.put("message", "Internal Server Error");
        }
        return response;
    }

    public void executeAddFlow(String modalType, int srcHost, int dstHost, ByteBuffer buffer) throws Exception {
        String urlString = String.format("http://127.0.0.1:8188/api/flows?src_host=%d&dst_host=%d&modal_type=%s", srcHost,dstHost,modalType);
        JSONObject response = utilityResponse(urlString, null, "GET");
        String[] involvedSwitches = response.getJSONObject("data").getString("data").split(",");
        log.info("involvedSwitches: {}", (Object) involvedSwitches);
        for(int i=0;i<involvedSwitches.length;i++){
            String[] parts = involvedSwitches[i].split("/");
            String deviceID = parts[0];
            int port = Integer.parseInt(parts[1]);
            postFlow(modalType, deviceID, port, buffer);
        }
    }

    public void postFlow(String modalType, String deviceID, int port, ByteBuffer buffer) {
        DeviceId deviceId = DeviceId.deviceId(deviceID);
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