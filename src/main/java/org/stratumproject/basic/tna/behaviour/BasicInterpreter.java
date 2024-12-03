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
                CoreService coreService = handler().get(CoreService.class);
                ApplicationId appId = coreService.getAppId("org.stratumproject.basic-tna");
                FlowRuleService flowRuleService = handler().get(FlowRuleService.class);
                ModalHandler modalHandler = new ModalHandler(appId, flowRuleService);
                modalHandler.handleModalPacket(pktType, ethPkt.getPayload().serialize(), deviceId);
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
