// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

// Do not modify this file manually, use `make constants` to generate this file.

package org.stratumproject.basic.tna.behaviour;

import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiPacketMetadataId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
/**
 * P4Info constants.
 */
public final class P4InfoConstants {

    // hide default constructor
    private P4InfoConstants() {
    }

    // 多模态
    public static final PiMatchFieldId SRC_ID =
            PiMatchFieldId.of("hdr.id.srcIdentity");
    public static final PiMatchFieldId DST_ID =
            PiMatchFieldId.of("hdr.id.dstIdentity");
    public static final PiMatchFieldId ETHERNET_DST =
            PiMatchFieldId.of("hdr.ethernet.dst_addr");
    public static final PiMatchFieldId IPV4_DST =
            PiMatchFieldId.of("hdr.ipv4.dstAddr");
    public static final PiMatchFieldId DEST_GUID =
            PiMatchFieldId.of("hdr.mf.dest_guid");
    public static final PiMatchFieldId LAT =
            PiMatchFieldId.of("hdr.gbc.geoAreaPosLat");
    public static final PiMatchFieldId LON =
            PiMatchFieldId.of("hdr.gbc.geoAreaPosLon");
    public static final PiMatchFieldId DISA =
            PiMatchFieldId.of("hdr.gbc.disa");
    public static final PiMatchFieldId DISB =
            PiMatchFieldId.of("hdr.gbc.disb");
    public static final PiMatchFieldId NDN_PREFIX_CODE =
            PiMatchFieldId.of("hdr.ndn.ndn_prefix.code");
    public static final PiMatchFieldId NAME_TLV_COMPONENTS =
            PiMatchFieldId.of("hdr.ndn.name_tlv.components[0].value");
    public static final PiMatchFieldId CONTENT_TLV =
            PiMatchFieldId.of("hdr.ndn.content_tlv.value");


    public static final PiTableId INGRESS_TABLE_IPv4 =
           PiTableId.of("ingress.routing_v4_table");
    public static final PiActionId INGRESS_TABLE_IPv4_SET_OUTPUT =
            PiActionId.of("ingress.set_next_v4_hop");
    public static final PiActionId INGRESS_TABLE_IPv4_DROP =
            PiActionId.of("ingress.drop");
            
    public static final PiTableId INGRESS_TABLE_MF =
           PiTableId.of("ingress.routing_mf_table");
    public static final PiActionId INGRESS_TABLE_MF_SET_OUTPUT =
            PiActionId.of("ingress.set_next_mf_hop");
    public static final PiActionId INGRESS_TABLE_MF_DROP =
            PiActionId.of("ingress.drop");
            
    public static final PiTableId INGRESS_TABLE_GEO =
           PiTableId.of("ingress.routing_geo_table");
    public static final PiActionId INGRESS_TABLE_GEO_SET_OUTPUT =
            PiActionId.of("ingress.geo_ucast_route");
    public static final PiActionId INGRESS_TABLE_GEO_DROP =
            PiActionId.of("ingress.drop");

    public static final PiTableId INGRESS_TABLE_NDN =
           PiTableId.of("ingress.routing_ndn_table");
    public static final PiActionId INGRESS_TABLE_NDN_SET_OUTPUT =
            PiActionId.of("ingress.set_next_ndn_hop");
    public static final PiActionId INGRESS_TABLE_NDN_DROP =
            PiActionId.of("ingress.drop");


    public static final PiTableId INGRESS_TABLE_ID =
           PiTableId.of("ingress.routing_id_table");
    public static final PiActionId INGRESS_TABLE_ID_SET_OUTPUT =
            PiActionId.of("ingress.set_next_id_hop");
    public static final PiActionId INGRESS_TABLE_ID_DROP =
            PiActionId.of("ingress.drop");   

    public static final PiTableId INGRESS_TABLE_FLEXIP =
           PiTableId.of("ingress.routing_flexip_table");
    public static final PiActionId INGRESS_TABLE_FLEXIP_SET_OUTPUT =
            PiActionId.of("ingress.set_next_flexip_hop");
    public static final PiActionId INGRESS_TABLE_FLEXIP_DROP =
            PiActionId.of("ingress.drop");  

    // Header field IDs
    public static final PiMatchFieldId HDR_EG_PORT =
            PiMatchFieldId.of("eg_port");
    public static final PiMatchFieldId HDR_ETH_DST =
            PiMatchFieldId.of("eth_dst");
    public static final PiMatchFieldId HDR_ETH_SRC =
            PiMatchFieldId.of("eth_src");
    public static final PiMatchFieldId HDR_ETH_TYPE =
            PiMatchFieldId.of("hdr.ethernet.ether_type");
    public static final PiMatchFieldId HDR_IG_PORT =
            PiMatchFieldId.of("ig_port");
    public static final PiMatchFieldId HDR_IP_PROTO =
            PiMatchFieldId.of("ip_proto");
    public static final PiMatchFieldId HDR_IPV4_DST =
            PiMatchFieldId.of("ipv4_dst");
    public static final PiMatchFieldId HDR_IPV4_SRC =
            PiMatchFieldId.of("ipv4_src");
    public static final PiMatchFieldId HDR_L4_DPORT =
            PiMatchFieldId.of("l4_dport");
    public static final PiMatchFieldId HDR_L4_SPORT =
            PiMatchFieldId.of("l4_sport");
    public static final PiTableId BASIC_EGRESS_STATS_FLOWS =
            PiTableId.of("BasicEgress.stats.flows");
    public static final PiTableId BASIC_INGRESS_TABLE0_TABLE0 =
            PiTableId.of("ingress.table0_control.table0");
    // Indirect Counter IDs
    public static final PiActionId BASIC_INGRESS_TABLE0_COPY_TO_CPU =
            PiActionId.of("ingress.table0_control.send_to_cpu");
    public static final PiActionId BASIC_INGRESS_TABLE0_DROP =
            PiActionId.of("ingress.table0_control.drop");
    public static final PiActionId BASIC_INGRESS_TABLE0_SET_OUTPUT =
            PiActionId.of("BasicIngress.table0.set_egress_port");
    public static final PiActionId NOP = PiActionId.of("nop");
    // Action Param IDs
    public static final PiActionParamId CPU_PORT =
            PiActionParamId.of("cpu_port");
    public static final PiActionParamId PORT_NUM =
            PiActionParamId.of("port_num");
    public static final PiPacketMetadataId EGRESS_PORT =
            PiPacketMetadataId.of("egress_port");
    public static final int EGRESS_PORT_BITWIDTH = 32;
    public static final PiPacketMetadataId INGRESS_PORT =
            PiPacketMetadataId.of("ingress_port");
    public static final int INGRESS_PORT_BITWIDTH = 32;
    public static final PiPacketMetadataId PAD0 = PiPacketMetadataId.of("pad0");
    public static final int PAD0_BITWIDTH = 7;

}
