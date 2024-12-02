// Copyright 2017-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

package org.stratumproject.basic.tna.behaviour;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.primitives.UnsignedInteger;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IP;
import org.onlab.packet.IPacket;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.DriverHandler;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.instructions.PiInstruction;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiPacketMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;
import org.slf4j.Logger;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Map;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static java.lang.String.format;
import static java.util.stream.Collectors.toList;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.PortNumber.TABLE;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;
import static org.slf4j.LoggerFactory.getLogger;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreter.mapTable0Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreterFlexIP.mapTableFlexIPTreatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreterID.mapTableIDTreatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreterIPv4.mapTableIPv4Treatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreterGEO.mapTableGEOTreatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreterNDN.mapTableNDNTreatment;
import static org.stratumproject.basic.tna.behaviour.BasicTreatmentInterpreterMF.mapTableMFTreatment;


/**
 * Interpreter for fabric-tna pipeline.
 */
public class BasicInterpreter extends AbstractBasicHandlerBehavior
        implements PiPipelineInterpreter {
    private static final Logger log = getLogger(BasicInterpreter.class);
    private static final Set<PiTableId> TABLE0_CTRL_TBLS = ImmutableSet.of(
            P4InfoConstants.BASIC_INGRESS_TABLE0_TABLE0,
            P4InfoConstants.INGRESS_TABLE_IPV4,
            P4InfoConstants.INGRESS_TABLE_MF,
            P4InfoConstants.INGRESS_TABLE_GEO,
            P4InfoConstants.INGRESS_TABLE_NDN,
            P4InfoConstants.INGRESS_TABLE_ID,
            P4InfoConstants.INGRESS_TABLE_FLEXIP);
    private static final Map<Integer, PiTableId> TABLE_MAP =
            new ImmutableMap.Builder<Integer, PiTableId>()
                    .put(0, P4InfoConstants.BASIC_INGRESS_TABLE0_TABLE0)
                    .put(P4InfoConstants.TABLEID_IPV4, P4InfoConstants.INGRESS_TABLE_IPV4)
                    .put(P4InfoConstants.TABLEID_MF, P4InfoConstants.INGRESS_TABLE_MF)
                    .put(P4InfoConstants.TABLEID_GEO, P4InfoConstants.INGRESS_TABLE_GEO)
                    .put(P4InfoConstants.TABLEID_NDN, P4InfoConstants.INGRESS_TABLE_NDN)
                    .put(P4InfoConstants.TABLEID_ID, P4InfoConstants.INGRESS_TABLE_ID)
                    .put(P4InfoConstants.TABLEID_FLEXIP, P4InfoConstants.INGRESS_TABLE_FLEXIP)
                    .build();
    private static final ImmutableMap<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            ImmutableMap.<Criterion.Type, PiMatchFieldId>builder()
                    .put(Criterion.Type.IN_PORT, P4InfoConstants.HDR_IG_PORT)
                    .put(Criterion.Type.ETH_DST, P4InfoConstants.HDR_ETH_DST)
                    .put(Criterion.Type.ETH_SRC, P4InfoConstants.HDR_ETH_SRC)
                    .put(Criterion.Type.ETH_TYPE, P4InfoConstants.HDR_ETH_TYPE)
                    .put(Criterion.Type.IPV4_DST, P4InfoConstants.HDR_IPV4_DST)
                    .put(Criterion.Type.IPV4_SRC, P4InfoConstants.HDR_IPV4_SRC)
                    .put(Criterion.Type.IP_PROTO, P4InfoConstants.HDR_IP_PROTO)
                    .put(Criterion.Type.UDP_DST, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.UDP_SRC, P4InfoConstants.HDR_L4_SPORT)
                    .put(Criterion.Type.TCP_DST, P4InfoConstants.HDR_L4_DPORT)
                    .put(Criterion.Type.TCP_SRC, P4InfoConstants.HDR_L4_SPORT)
                    .build();

    private BasicTreatmentInterpreter treatmentInterpreter;

    /**
     * Creates a new instance of this behavior with the given capabilities.
     *
     * @param capabilities capabilities
     */
    public BasicInterpreter(BasicCapabilities capabilities) {
        super(capabilities);
        instantiateTreatmentInterpreter();
    }

    /**
     * Create a new instance of this behaviour. Used by the abstract projectable
     * model (i.e., {@link org.onosproject.net.Device#as(Class)}.
     */
    public BasicInterpreter() {
        super();
    }

    private void instantiateTreatmentInterpreter() {
        this.treatmentInterpreter = new BasicTreatmentInterpreter(this.capabilities);
    }

    @Override
    public void setHandler(DriverHandler handler) {
        super.setHandler(handler);
        instantiateTreatmentInterpreter();
    }

    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        // The only use case for Index ID->PiTableId is when using the single
        // table pipeliner. fabric.p4 is never used with such pipeliner.
        return Optional.ofNullable(TABLE_MAP.get(flowRuleTableId));
    }

    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId)
            throws PiInterpreterException {
        if (TABLE0_CTRL_TBLS.contains(piTableId)) {
            return mapTable0Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.INGRESS_TABLE_IPV4)) {
            return mapTableIPv4Treatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.INGRESS_TABLE_MF)) {
            return mapTableMFTreatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.INGRESS_TABLE_GEO)) {
            return mapTableGEOTreatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.INGRESS_TABLE_NDN)) {
            return mapTableNDNTreatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.INGRESS_TABLE_ID)) {
            return mapTableIDTreatment(treatment, piTableId);
        } else if (piTableId.equals(P4InfoConstants.INGRESS_TABLE_FLEXIP)) {
            return mapTableFlexIPTreatment(treatment, piTableId);
        } else {
            throw new PiInterpreterException(format(
                    "Treatment mapping not supported for table '%s'", piTableId));
        }
    }

    private PiPacketOperation createPiPacketOperation(
            ByteBuffer data, long portNumber, boolean doForwarding)
            throws PiInterpreterException {
        Collection<PiPacketMetadata> metadata = createPacketMetadata(portNumber, doForwarding);
        return PiPacketOperation.builder()
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(metadata)
                .build();
    }

    private Collection<PiPacketMetadata> createPacketMetadata(
            long portNumber, boolean doForwarding)
            throws PiInterpreterException {
        try {
            ImmutableList.Builder<PiPacketMetadata> builder = ImmutableList.builder();
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.PAD0)
                    .withValue(copyFrom(0)
                            .fit(P4InfoConstants.PAD0_BITWIDTH))
                    .build());
            builder.add(PiPacketMetadata.builder()
                    .withId(P4InfoConstants.EGRESS_PORT)
                    .withValue(copyFrom(portNumber)
                            .fit(P4InfoConstants.EGRESS_PORT_BITWIDTH))
                    .build());

            return builder.build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format(
                    "Port number '%d' too big, %s", portNumber, e.getMessage()));
        }
    }

    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet)
            throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        // We support only OUTPUT instructions.
        List<Instructions.OutputInstruction> outInstructions = treatment
                .allInstructions()
                .stream()
                .filter(i -> i.type().equals(OUTPUT))
                .map(i -> (Instructions.OutputInstruction) i)
                .collect(toList());

        if (treatment.allInstructions().size() != outInstructions.size()) {
            // There are other instructions that are not of type OUTPUT.
            throw new PiInterpreterException("Treatment not supported: " + treatment);
        }

        ImmutableList.Builder<PiPacketOperation> builder = ImmutableList.builder();
        for (Instructions.OutputInstruction outInst : outInstructions) {
            if (outInst.port().equals(TABLE)) {
                // Logical port. Forward using the switch tables like a regular packet.
                builder.add(createPiPacketOperation(packet.data(), 0, true));
            } else if (outInst.port().equals(FLOOD)) {
                // Logical port. Create a packet operation for each switch port.
                final DeviceService deviceService = handler().get(DeviceService.class);
                for (Port port : deviceService.getPorts(packet.sendThrough())) {
                    builder.add(createPiPacketOperation(packet.data(), port.number().toLong(), false));
                }
            } else if (outInst.port().isLogical()) {
                throw new PiInterpreterException(format(
                        "Output on logical port '%s' not supported", outInst.port()));
            } else {
                // Send as-is to given port bypassing all switch tables.
                builder.add(createPiPacketOperation(packet.data(), outInst.port().toLong(), false));
            }
        }
        return builder.build();
    }

    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn, DeviceId deviceId) throws PiInterpreterException {
        // Assuming that the packet is ethernet, which is fine since fabric.p4
        // can deparse only ethernet packets.
        Ethernet ethPkt;
        log.warn("new Pkt");
        try {
            ethPkt = Ethernet.deserializer().deserialize(packetIn.data().asArray(), 0,
                                                         packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

        // Returns the ingress port packet metadata.
        Optional<PiPacketMetadata> packetMetadata = packetIn.metadatas()
                .stream().filter(m -> m.id().equals(P4InfoConstants.INGRESS_PORT))
                .findFirst();
        final int pktType;

        if (packetMetadata.isPresent()) {
            try {
                ImmutableByteSequence portByteSequence = packetMetadata.get()
                        .value().fit(P4InfoConstants.INGRESS_PORT_BITWIDTH);
                UnsignedInteger ui =
                    UnsignedInteger.fromIntBits(portByteSequence.asReadOnlyBuffer().getInt());
                ConnectPoint receivedFrom =
                    new ConnectPoint(deviceId, PortNumber.portNumber(ui.longValue()));
                if (!receivedFrom.port().hasName()) {
                    receivedFrom = translateSwitchPort(receivedFrom);
                }
                ByteBuffer rawData = ByteBuffer.wrap(packetIn.data().asArray());
                pktType = ethPkt.getEtherType() & 0xffff;
                log.warn("Packet: {}", ethPkt);
                log.warn("new Pkt is {} type from device {} port {}",pktType,deviceId,portByteSequence);
                byte[] payload = ethPkt.getPayload().serialize();
                // 解析模态、计算路径、下发流表
                handleModalPacket(pktType, ethPkt.getPayload().serialize(), deviceId);
                // sendToMMQueue(ethPkt);

                // 构造PakcetOut数据包发回原始数据
//                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
//                        .setOutput(receivedFrom.port()).build();
//                DefaultOutboundPacket outPakcet = new DefaultOutboundPacket(deviceId,treatment,rawData);
//                log.warn("Send Packet: {}",outPakcet);
//                mapOutboundPacket(outPakcet).forEach(op-> packetOut);

                return new DefaultInboundPacket(receivedFrom, ethPkt, rawData);
            } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
                throw new PiInterpreterException(format(
                        "Malformed metadata '%s' in packet-in received from '%s': %s",
                        P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
            }
        } else {
            throw new PiInterpreterException(format(
                    "Missing metadata '%s' in packet-in received from '%s': %s",
                    P4InfoConstants.INGRESS_PORT, deviceId, packetIn));
        }
    }

    // public void sendToMMQueue(Ethernet ethPkt) throws ClientException {
    //     String endpoint = "localhost:8081";
    //     String topic = "TestTopic";
    //     ClientServiceProvider provider = ClientServiceProvider.loadService();
    //     ClientConfigurationBuilder builder = ClientConfiguration.newBuilder().setEndpoints(endpoint);
    //     ClientConfiguration configuration = builder.build();
    //     Producer producer = provider.newProducerBuilder()
    //         .setTopics(topic)
    //         .setClientConfiguration(configuration)
    //         .build();
    //     // 普通消息发送。
    //     Message message = provider.newMessageBuilder()
    //         .setTopic(topic)
    //         // 设置消息索引键，可根据关键字精确查找某条消息。
    //         .setKeys(String.format("%d",ethPkt.getEtherType()))
    //         // 设置消息Tag，用于消费端根据指定Tag过滤消息。
    //         .setTag("messageTag")
    //         // 消息体。
    //         .setBody("test modal packet".getBytes())
    //         .build();
    //     try {
    //         // 发送消息，需要关注发送结果，并捕获失败等异常。
    //         SendReceipt sendReceipt = producer.send(message);
    //         log.info("Send message successfully, messageId={}", sendReceipt.getMessageId());
    //     } catch (ClientException e) {
    //         log.error("Failed to send message", e);
    //     }
    //     // producer.close();
    // }

    public int vmx = 1;

    private String decimal2Hex(int value, int length) {
        String hexNumber = Integer.toHexString(value).toUpperCase();
        if(length == 8) {
            return String.format("%8s", hexNumber).replace(' ','0');
        }
        return String.format("%4s", hexNumber).replace(' ','0');
    }

    private String ip2Hex(String ipAddr) {
        String[] parts = ipAddr.split("\\.");
        String hexAddr = "";
        for(int i=0;i<parts.length;i++) {
            int part = Integer.parseInt(parts[i]);
            String hexPart = Integer.toHexString(part).toUpperCase();
            hexAddr = hexAddr + String.format("%2s", hexPart).replace(' ','0');
        }
        return hexAddr;
    }

    // API方式下发流表
    // public JSONObject generateIDFlows(int switchID, int port, int srcIdentifier, int dstIdentifier) {
    //     {
    //         "flows": [
    //             {
    //                 "priority": 10,
    //                 "timeout": 0,
    //                 "isPermanent": "true",
    //                 "tableId": "5",     // id的tableId=5
    //                 "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
    //                 "treatment": {
    //                     "instructions": [
    //                         {
    //                             "type": "PROTOCOL_INDEPENDENT",
    //                             "subtype": "ACTION",
    //                             "actionId": "ingress.set_next_id_hop",
    //                             "actionParams": {
    //                                 "dst_port": f"{port}"
    //                             }
    //                         }
    //                     ]
    //                 },
    //                 "clearDeferred": "true",
    //                 "selector": {
    //                     "criteria": [
    //                         {
    //                             "type": "PROTOCOL_INDEPENDENT",
    //                             "matches": [
    //                                 {
    //                                     "field": "hdr.ethernet.ether_type",
    //                                     "match": "exact",
    //                                     "value": "0812"
    //                                 },
    //                                 {
    //                                     "field": "hdr.id.srcIdentity",
    //                                     "match": "exact",
    //                                     "value": decimal_to_8hex(identity_src)
    //                                 },
    //                                 {
    //                                     "field": "hdr.id.dstIdentity",
    //                                     "match": "exact",
    //                                     "value": decimal_to_8hex(identity_dst)
    //                                 },
    //                             ]
    //                         }
    //                     ]
    //                 }
    //             }
    //         ]
    //     }
    //     int srcIdentity = 202271720 + vmx * 100000 + srcIdentifier - 64;
    //     int dstIdentity = 202271720 + vmx * 100000 + dstIdentifier - 64;
    //     int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
    //     log.warn("generateIDFlows srcIdentifier:{}, dstIdentifier:{}, srcIdentity:{}, dstIdentity:{}",
    //             srcIdentifier, dstIdentifier, srcIdentity, dstIdentity);
    //     String deviceID = String.format("device:domain1:group4:level%d:s%d",level, switchID + vmx * 100);
    //     JSONObject flowObject = new JSONObject();
    //     flowObject.put("priority", 10);
    //     flowObject.put("timeout", 0);
    //     flowObject.put("isPermanent", "true");
    //     flowObject.put("tableId",5);                // id的tableId=5
    //     flowObject.put("deviceId", deviceID);
    //     flowObject.put("treatment", new JSONObject()
    //             .put("instructions", new JSONArray()
    //                     .put(new JSONObject()
    //                             .put("type", "PROTOCOL_INDEPENDENT")
    //                             .put("subtype", "ACTION")
    //                             .put("actionId", "ingress.set_next_id_hop")
    //                             .put("actionParams", new JSONObject()
    //                                     .put("dst_port", String.format("%s", port))))));
    //     flowObject.put("clearDeferred", "true");
    //     flowObject.put("selector", new JSONObject()
    //             .put("criteria", new JSONArray()
    //                     .put(new JSONObject()
    //                             .put("type", "PROTOCOL_INDEPENDENT")
    //                             .put("matches", new JSONArray()
    //                                     .put(new JSONObject()
    //                                             .put("field", "hdr.ethernet.ether_type")
    //                                             .put("match", "exact")
    //                                             .put("value", "0812"))
    //                                     .put(new JSONObject()
    //                                             .put("field", "hdr.id.srcIdentity")
    //                                             .put("match", "exact")
    //                                             .put("value", decimal2Hex(srcIdentity,8)))
    //                                     .put(new JSONObject()
    //                                             .put("field", "hdr.id.dstIdentity")
    //                                             .put("match", "exact")
    //                                             .put("value", decimal2Hex(dstIdentity,8)))))));
    //     return new JSONObject().put("flows", new JSONArray().put(flowObject));
    // }

    // public void postFlow(String modalType, int switchID, int port, int srcIdentifier, int dstIdentifier) {
    //     String IP = "218.199.84.171";
    //     String APP_ID = "org.stratumproject.basic-tna";
    //     String urlString = String.format("http://%s:8181/onos/v1/flows?appId=%s",IP,APP_ID);
    //     String auth = "onos:rocks";
    //     String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

    //     JSONObject jsonData = null;

    //     switch (modalType) {
    //         case "ip":
    //             jsonData = generateIPFlows(switchID, port, srcIdentifier, dstIdentifier);
    //             break;
    //         case "id":
    //             jsonData = generateIDFlows(switchID, port, srcIdentifier, dstIdentifier);
    //             break;
    //         case "geo":
    //             // jsonData = generateGEOFlows(switchID, port, srcIdentifier, dstIdentifier);
    //             break;
    //         case "mf":
    //             jsonData = generateMFFlows(switchID, port, srcIdentifier, dstIdentifier);
    //             break;
    //         case "ndn":
    //             jsonData = generateNDNFlows(switchID, port, srcIdentifier, dstIdentifier);
    //             break;
    //         default:
    //             log.error("Invalid modal type: {}", modalType);
    //     }

    //     // 发送请求
    //     try {
    //         log.warn("------------data------------\n");
    //         URL url = new URL(urlString);
    //         HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    //         connection.setRequestMethod("POST");
    //         connection.setRequestProperty("Content-Type", "application/json");
    //         connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
    //         connection.setDoOutput(true);

    //         // 发送JSON数据
    //         try (OutputStream os = connection.getOutputStream()) {
    //             byte[] input = jsonData.toString().getBytes("utf-8");
    //             os.write(input, 0, input.length);
    //         }

    //         int responseCode = connection.getResponseCode();
    //         if (responseCode == HttpURLConnection.HTTP_OK) {
    //             log.warn("Success: " + connection.getResponseMessage());
    //         } else {
    //             log.warn("Status Code: " + responseCode);
    //             log.warn("Response Body: " + connection.getResponseMessage());
    //         }
    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }
    //     return;
    // }

    public byte[] int2Bytes(int value) {
        return new byte[]{(byte)((value>>>24)&0xff), (byte)((value>>>16)&0xff), (byte)((value>>>8)&0xff), (byte)(value&0xff)};
    }

    public byte[] short2Bytes(short value) {
        return new byte[]{(byte)((value>>>8)&0xff), (byte)(value&0xff)};
    }

    private int getIdentity(int vmx, int id) {
        return 202271720 + vmx * 100000 + id - 64;
    }

    public byte[] ipString2Bytes(String value) {
        byte[] rnt = new byte[4];
        String[] parts = value.split("\\.");
        for(int i=0;i<parts.length;i++) {
            int part = Integer.parseInt(parts[i]);
            rnt[i] = (byte) part;
        }
        return rnt;
    }

    private String getIPv4(int vmx, int id) {
        return String.format("172.20.%d.%d", vmx + 1, id - 64 + 12);
    }

    private int getMFGuid(int vmx, int id) {
        return 1 + vmx * 100 + id - 64;
    }

    private int getNDNName(int vmx, int id) {
        return 202271720 + vmx * 100000 + id - 64;
    }

    private short getNDNContent(int vmx, int id){
        int result = 2048 + vmx * 100 + id - 64;
        return (short) result;
    }

    public FlowRule applyIPv4Flow(DeviceId deviceId, ApplicationId appId, int port, int srcId, int dstId) {
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        int etherType = 0x0800;
        PiMatchFieldId srcAddrFieldId = PiMatchFieldId.of("hdr.ipv4.srcAddr");
        String srcIdentifier = getIPv4(vmx, srcId);
        byte[] srcIPv4Address = ipString2Bytes(srcIdentifier);
        PiMatchFieldId dstAddrFieldId = PiMatchFieldId.of("hdr.ipv4.dstAddr");
        String dstIdentifier = getIPv4(vmx, dstId);
        byte[] dstIPv4Address = ipString2Bytes(dstIdentifier);
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, etherType)
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
            .forTable(1)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }

    public FlowRule applyIDFlow(DeviceId deviceId, ApplicationId appId, int port, int srcId, int dstId){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        int etherType = 0x0812;
        PiMatchFieldId srcIdentityFieldId = PiMatchFieldId.of("hdr.id.srcIdentity");
        int srcIdentifier = getIdentity(vmx, srcId);
        byte[] srcIdentity = int2Bytes(srcIdentifier);
        int dstIdentifier = getIdentity(vmx, dstId);
        PiMatchFieldId dstIdentityFieldId = PiMatchFieldId.of("hdr.id.dstIdentity");
        byte[] dstIdentity = int2Bytes(dstIdentifier);
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, etherType)
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
            .forTable(5)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }

    public FlowRule applyGEOFlow(DeviceId deviceId, ApplicationId appId, int port, int srcId, int dstId, ByteBuffer buffer){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        int etherType = 0x8947;
        PiMatchFieldId geoAreaPosLatFieldId = PiMatchFieldId.of("hdr.gbc.geoAreaPosLat");
        byte[] geoAreaPosLat = new byte[4];
        buffer.position(40);
        for(int i=0;i<4;i++) {
            geoAreaPosLat[i] = buffer.get();
        }
        PiMatchFieldId geoAreaPosLonFieldId = PiMatchFieldId.of("hdr.gbc.geoAreaPosLon");
        byte[] geoAreaPosLon = new byte[4];
        buffer.position(44);
        for(int i=0;i<4;i++) {
            geoAreaPosLon[i] = buffer.get();
        }
        PiMatchFieldId disaFieldId = PiMatchFieldId.of("hdr.gbc.disa");
        PiMatchFieldId disbFieldId = PiMatchFieldId.of("hdr.gbc.disb");
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, etherType)
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
            .forTable(3)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }

    public FlowRule applyMFFlow(DeviceId deviceId, ApplicationId appId, int port, int srcId, int dstId){
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        int etherType = 0x27c0;
        PiMatchFieldId srcGuidFieldId = PiMatchFieldId.of("hdr.mf.src_guid");
        int srcIdentifier = getMFGuid(vmx, srcId);
        byte[] srcMFGuid = int2Bytes(srcIdentifier);
        PiMatchFieldId dstGuidFieldId = PiMatchFieldId.of("hdr.mf.dest_guid");
        int dstIdentifier = getMFGuid(vmx, dstId);
        byte[] dstMFGuid = int2Bytes(dstIdentifier);
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, etherType)
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
            .forTable(2)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }

    public FlowRule applyNDNFlow(DeviceId deviceId, ApplicationId appId, int port, int srcId, int dstId) {
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        int etherType = 0x8624;
        PiMatchFieldId ndnCodeFieldId = PiMatchFieldId.of("hdr.ndn.ndn_prefix.code");
        int ndnCode = 6;
        PiMatchFieldId srcNDNNameFieldId = PiMatchFieldId.of("hdr.ndn.name_tlv.components[0].value");
        int srcIdentifier = getNDNName(vmx, srcId);
        byte[] srcNDNName = int2Bytes(srcIdentifier);
        PiMatchFieldId dstNDNNameFieldId = PiMatchFieldId.of("hdr.ndn.name_tlv.components[1].value");
        int dstIdentifier = getNDNName(vmx, dstId);
        byte[] dstNDNName = int2Bytes(dstIdentifier);
        PiMatchFieldId ndnContentFieldId = PiMatchFieldId.of("hdr.ndn.content_tlv.value");
        short contentIdentifier = getNDNContent(vmx, srcId);
        byte[] ndnContent = short2Bytes(contentIdentifier);
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, etherType)
            .matchExact(ndnCodeFieldId, ndnCode)
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
            .forTable(4)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }

    public FlowRule applyFlexIPFlow(DeviceId deviceId, ApplicationId appId, int port, int srcId, int dstId, ByteBuffer buffer) {
        int flexip_prefix = ((buffer.get(0) & 0xff) << 24 | (buffer.get(1) & 0xff) << 16 | (buffer.get(2) & 0xff) << 8 | (buffer.get(3) & 0xff));
        int srcFormat = flexip_prefix >> 26 & 0x3;
        int dstFormat = flexip_prefix >> 24 & 0x3;
        int srcLength = flexip_prefix >> 12 & 0x7ff;
        int dstLength = flexip_prefix & 0x7ff;
        log.warn("flexip_prefix:{}, srcLength:{}, dstLength:{}", flexip_prefix, srcLength, dstLength);
        PiMatchFieldId etherTypeFieldId = PiMatchFieldId.of("hdr.ethernet.ether_type");
        int etherType = 0x3690;
        PiMatchFieldId srcFormatFieldId = PiMatchFieldId.of("hdr.flexip.srcFormat");
        PiMatchFieldId dstFormatFieldId = PiMatchFieldId.of("hdr.flexip.dstFormat");
        PiMatchFieldId srcAddrFieldId = PiMatchFieldId.of("hdr.flexip.srcAddr");
        byte[] srcAddr = new byte[srcLength/8];
        buffer.position(52-srcLength/8);
        for(int i=0;i<srcLength/8;i++) {
            srcAddr[i] = buffer.get();
        }
        log.warn("srcFlexIP:{}",srcAddr);
        // if (srcLength % 8 != 0) {
        //     byte lastByte = (byte)(buffer.get(4 + srcLength/8) & 0xff >> (8 - srcLength % 8));
        //     srcAddr = Arrays.copyOf(srcAddr, srcAddr.length + 1);
        //     srcAddr[srcAddr.length - 1] = lastByte;
        // }
        PiMatchFieldId dstAddrFieldId = PiMatchFieldId.of("hdr.flexip.dstAddr");
        byte[] dstAddr = new byte[dstLength/8];
        buffer.position(100-dstLength/8);
        for(int i=0;i<dstLength/8;i++) {
            dstAddr[i] = buffer.get();
        }
        log.warn("dstFlexIP:{}",dstAddr);
        // if (dstLength % 8 != 0) {
        //     byte lastByte = (byte)(buffer.get(4 + dstLength/8) & 0xff >> (8 - dstLength % 8));
        //     dstAddr = Arrays.copyOf(dstAddr, dstAddr.length + 1);
        //     dstAddr[dstAddr.length - 1] = lastByte;
        // }
        PiCriterion criteria = PiCriterion.builder()
            .matchExact(etherTypeFieldId, etherType)
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
            .forTable(6)
            .withPriority(10)
            .withHardTimeout(0)
            .withSelector(selector)
            .withTreatment(treatment)
            .makePermanent()
            .fromApp(appId)
            .build();
        return flowRule;
    }

    public void postFlow(String modalType, int switchID, int port, int srcHost, int dstHost, ByteBuffer buffer) {
        CoreService coreService = handler().get(CoreService.class);
        ApplicationId appId = coreService.getAppId("org.stratumproject.basic-tna");
        FlowRuleService flowRuleService = handler().get(FlowRuleService.class);
        int level = (int) (Math.log(switchID)/Math.log(2)) + 1;
        int srcId = srcHost - vmx * 100;
        int dstId = dstHost - vmx * 100; 
        DeviceId deviceId = DeviceId.deviceId(String.format("device:domain1:group4:level%d:s%d",level, switchID + vmx * 100));
        FlowRule flowRule;
        switch (modalType) {
            case "ip":
                flowRule = applyIPv4Flow(deviceId, appId, port, srcId, dstId);
                flowRuleService.applyFlowRules(flowRule);
                log.warn("IPv4 flow rule applied! {}", flowRule);
                break;
            case "id":
                flowRule = applyIDFlow(deviceId, appId, port, srcId, dstId);
                flowRuleService.applyFlowRules(flowRule);
                log.warn("ID flow rule applied! {}", flowRule);
                break;
            case "geo":
                flowRule = applyGEOFlow(deviceId, appId, port, srcId, dstId, buffer);
                flowRuleService.applyFlowRules(flowRule);
                log.warn("GEO flow rule applied! {}", flowRule);
                break;
            case "mf":
                flowRule = applyMFFlow(deviceId, appId, port, srcId, dstId);
                flowRuleService.applyFlowRules(flowRule);
                log.warn("MF flow rule applied! {}", flowRule);
                break;
            case "ndn":
                flowRule = applyNDNFlow(deviceId, appId, port, srcId, dstId);
                flowRuleService.applyFlowRules(flowRule);
                log.warn("NDN flow rule applied! {}", flowRule);
                break;
            case "flexip":
                flowRule = applyFlexIPFlow(deviceId, appId, port, srcId, dstId, buffer);
                flowRuleService.applyFlowRules(flowRule);
                log.warn("FlexIP flow rule applied! {}", flowRule);
                break;
            default:
                log.error("Invalid modal type: {}", modalType);
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
    
    private int transferIP2Host(int param) {
        log.warn("transferIP2Host param:{}", param);
        int x = ((param & 0xffff) >> 8) - 1;
        int i = (param & 0xff) + 64 - 12;
        return x * 100 + i;
    }

    private int transferID2Host(int param) {
        log.warn("transferID2Host param:{}",param);
        int x = (param - 202271720) / 100000;
        int i = param - 202271720 - x * 100000 + 64;
        return x * 100 + i;
    }

    private int transferMF2Host(int param) {
        log.warn("transferMF2Host param:{}", param);
        int x = (param - 1) / 100;
        int i = param - 1 - x * 100 + 64;
        return x * 100 + i;
    }

    private int transferNDN2Host(int param) {
        log.warn("transferNDN2Host param:{}", param);
        int x = (param - 202271720) / 100000;
        int i = param - 202271720 - x * 100000 + 64;
        return x * 100 + i;
    }

    private int transferGEO2Host(int param) {
        log.warn("transferGEO2Host param:{}", param);
        return vmx * 100 + param + 63;
    }

    public void handleModalPacket(int pktType, byte[] payload, DeviceId deviceId) {
        String modalType = "";
        int srcHost = 0, dstHost = 0;
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        log.warn("payload: {}, buffer: {}, deviceId: {}", payload, buffer, deviceId);
        pktType = (pktType + 65536) % 65536;            // pktType是short类型，可能溢出成负数
        switch(pktType){
            case 0x0800:    // IP
                modalType = "ip";
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
                int format_restrained = 0;
                int format_extendable = 1;
                int format_hierarchical = 2;
                int format_multiSemantics = 3;

                int flexip_prefix = ((buffer.get(0) & 0xff) << 24 | (buffer.get(1) & 0xff) << 16 | (buffer.get(2) & 0xff) << 8 | (buffer.get(3) & 0xff));
                int srcFormat = flexip_prefix >> 26 & 0x3;
                int dstFormat = flexip_prefix >> 24 & 0x3;
                int srcLength = flexip_prefix >> 12 & 0x7ff;
                int dstLength = flexip_prefix & 0x7ff;
                // 获取srcHost
                buffer.position(52-srcLength/8);
                if (srcFormat == format_restrained) {
                    srcHost = vmx * 100 + (buffer.get() & 0xff);
                } else if (srcFormat == format_extendable) {
                    int srcIndex = buffer.get() & 0xff;
                    if (srcIndex == 240) {  // F0
                        byte[] FlexIP = new byte[2];
                        buffer.get(FlexIP, 0, 2);
                        int flexip = ((FlexIP[0] * 0xff) << 8) + 
                                     (FlexIP[1] & 0xff);
                        int x = (flexip - 2048) / 100;
                        int i = flexip - 2048 - x * 100 + 64;
                        srcHost = x * 100 + i;
                    } else if (srcIndex == 241) {   // F1
                        byte[] FlexIP = new byte[4];
                        buffer.get(FlexIP, 0, 4);
                        int flexip = ((FlexIP[0] & 0xff) << 24) + 
                                     ((FlexIP[1] & 0xff) << 16) + 
                                     ((FlexIP[2] & 0xff) << 8) + 
                                     (FlexIP[3] & 0xff);
                        int x = (flexip - 202271720) / 100000;
                        int i = flexip - 202271720 - x * 100000 + 64;
                        srcHost = x * 100 + i;
                    } else if (srcIndex == 242) {   // F2
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
                        long x = (flexip - (1L<<50)) / 100000000;
                        long i = flexip - (1L<<50) - x * 100000000 + 64;
                        srcHost = (int)(x * 100 + i);
                    } else {    // F4
                        byte[] FlexIP = new byte[32];
                        buffer.get(FlexIP, 0, 32);
                        long flexip = ((long)FlexIP[31] & 0xff) +
                                      (((long)FlexIP[30] & 0xff) << 8) + 
                                      (((long)FlexIP[29] & 0xff) << 16) + 
                                      (((long)FlexIP[28] & 0xff) << 24) + 
                                      (((long)FlexIP[27] & 0xff) << 32) + 
                                      (((long)FlexIP[26] & 0xff) << 40);
                        long x = flexip / 100000000000L;
                        long i = flexip - x * 100000000000L + 64L;
                        srcHost = (int)(x * 100 + i);
                    }
                } else {
                    int srcIndex = buffer.get() & 0xff;
                    int afterByte = buffer.get() & 0xff;
                    if (afterByte == 240) {     // F0
                        byte[] FlexIP = new byte[2];
                        buffer.get(FlexIP, 0, 2);
                        int flexip = ((FlexIP[0] & 0xff) << 8) + 
                                     (FlexIP[1] & 0xff);
                        int x = (flexip - 2048) / 100;
                        int i = flexip - 2048 - x * 100 + 64;
                        srcHost = x * 100 + i;
                    } else if (afterByte == 241) {      // F1
                        byte[] FlexIP = new byte[4];
                        buffer.get(FlexIP, 0, 4);
                        int flexip = ((FlexIP[0] & 0xff) << 24) + 
                                     ((FlexIP[1] & 0xff) << 16) + 
                                     ((FlexIP[2] & 0xff) << 8) + 
                                     (FlexIP[3] & 0xff);
                        int x = (flexip - 202271720) / 100000;
                        int i = flexip - 202271720 - x * 100000 + 64;
                        srcHost = x * 100 + i;
                    } else if (afterByte == 242) {      // F2
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
                        long x = (flexip - (1L<<50)) / 100000000;
                        long i = flexip - (1L<<50) - x * 100000000 + 64;
                        srcHost = (int)(x * 100 + i);
                    } else {
                        srcHost = vmx * 100 + afterByte;
                    }
                }
                // 获取dstHost
                buffer.position(100-dstLength/8);
                if (dstFormat == format_restrained) {
                    dstHost = vmx * 100 + (buffer.get() & 0xff);
                } else if (dstFormat == format_extendable) {
                    int dstIndex = buffer.get() & 0xff;
                    if (dstIndex == 240) {  // F0
                        byte[] FlexIP = new byte[2];
                        buffer.get(FlexIP, 0, 2);
                        int flexip = ((FlexIP[0] & 0xff) << 8) +
                                     (FlexIP[1] & 0xff);
                        int x = (flexip - 2048) / 100;
                        int i = flexip - 2048 - x * 100 + 64;
                        dstHost = x * 100 + i;
                    } else if (dstIndex == 241) {   // F1
                        byte[] FlexIP = new byte[4];
                        buffer.get(FlexIP, 0, 4);
                        int flexip = ((FlexIP[0] & 0xff) << 24) + 
                                     ((FlexIP[1] & 0xff) << 16) + 
                                     ((FlexIP[2] & 0xff) << 8) + 
                                     (FlexIP[3] & 0xff);
                        int x = (flexip - 202271720) / 100000;
                        int i = flexip - 202271720 - x * 100000 + 64;
                        dstHost = x * 100 + i;
                    } else if (dstIndex == 242) {   // F2
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
                        long x = (flexip - (1L<<50)) / 100000000L;
                        long i = flexip - (1L<<50) - x * 100000000L + 64L;
                        dstHost = (int)(x * 100 + i);
                    } else {    // F4
                        byte[] FlexIP = new byte[32];
                        buffer.get(FlexIP, 0, 32);
                        long flexip = ((long)FlexIP[31] & 0xff) +
                                      (((long)FlexIP[30] & 0xff) << 8) + 
                                      (((long)FlexIP[29] & 0xff) << 16) + 
                                      (((long)FlexIP[28] & 0xff) << 24) + 
                                      (((long)FlexIP[27] & 0xff) << 32) + 
                                      (((long)FlexIP[26] & 0xff) << 40);
                        long x = flexip / 100000000000L;
                        long i = flexip - x * 100000000000L + 64L;
                        dstHost = (int)(x * 100 + i);
                    }
                } else {
                    int dstIndex = buffer.get() & 0xff;
                    int afterByte = buffer.get() & 0xff;
                    if (afterByte == 240) {
                        byte[] FlexIP = new byte[2];
                        buffer.get(FlexIP, 0, 2);
                        int flexip = ((FlexIP[0] & 0xff) << 8) + 
                                     (FlexIP[1] & 0xff);
                        int x = (flexip - 2048) / 100;
                        int i = flexip - 2048 - x * 100 + 64;
                        dstHost = x * 100 + i;
                    } else if (afterByte == 241) {
                        byte[] FlexIP = new byte[4];
                        buffer.get(FlexIP, 0, 4);
                        int flexip = ((FlexIP[0] & 0xff) << 24) + 
                                     ((FlexIP[1] & 0xff) << 16) + 
                                     ((FlexIP[2] & 0xff) << 8) + 
                                     (FlexIP[3] & 0xff);
                        int x = (flexip - 202271720) / 100000;
                        int i = flexip - 202271720 - x * 100000 + 64;
                        dstHost = x * 100 + i;
                    } else if (afterByte == 242) {
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
                        long x = (flexip - (1L<<50)) / 100000000L;
                        long i = flexip - (1L<<50) - x * 100000000L + 64;
                        dstHost = (int)(x * 100 + i);
                    } else {
                        dstHost = vmx * 100 + afterByte;
                    }
                }
                log.warn("srcHost:{}, dstHost:{}", srcHost, dstHost);
                // srcHost = transferFlexIP2Host(srcFormat, buffer);
                // dstHost = transferFlexIP2Host(dstFormat, buffer);
                break;
        }
        if (modalType == "ip" || modalType == "id" || modalType == "geo" || modalType == "mf" || modalType == "ndn" || modalType == "flexip") {
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


    @Override
    public Optional<PiAction> getOriginalDefaultAction(PiTableId tableId) {
        return Optional.empty();
    }

    @Override
    public Optional<Long> mapLogicalPort(PortNumber port) {
      if (!port.equals(CONTROLLER)) {
          return Optional.empty();
      }
      return capabilities.cpuPort();
    }

    /* Connect point generated using sb metadata does not have port name
       we use the device service as translation service */
    private ConnectPoint translateSwitchPort(ConnectPoint connectPoint) {
        final DeviceService deviceService = handler().get(DeviceService.class);
        if (deviceService == null) {
            log.warn("Unable to translate switch port due to DeviceService not available");
            return connectPoint;
        }
        Port devicePort = deviceService.getPort(connectPoint);
        if (devicePort != null) {
            return new ConnectPoint(connectPoint.deviceId(), devicePort.number());
        }
        return connectPoint;
    }
}
