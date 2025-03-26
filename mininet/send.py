#!/usr/bin/env python3
import random
import socket
import sys
import struct
import math
import time
import subprocess
import json

from scapy.all import IP, TCP, Ether, Raw, get_if_hwaddr, get_if_list, sendp

# ethertype for each modal type
ip_ethertype = 0x0800
id_ethertype = 0x0812
geo_ethertype = 0x8947
mf_ethertype = 0x27c0
ndn_ethertype = 0x8624
flexip_ethertype = 0x3690

def getMacByVmx(vmx):
    return f"02:42:0a:01:00:0{vmx+2}"

# find the interface eth0
def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def float_to_custom_bin(number):
    # 转换输入为浮点数，防止传入的是字符串
    number = float(number)
    # 确定符号位并取绝对值
    sign_bit = '01' if number < 0 else '00'
    number = abs(number)

    # 分离整数部分和小数部分
    integer_part, fractional_part = divmod(number, 1)
    integer_part = int(integer_part)

    # 将整数部分转换为 15 位二进制
    integer_bits = format(integer_part, '015b')

    # 将小数部分转换为 15 位二进制
    fractional_bits = ''
    while len(fractional_bits) < 15:
        fractional_part *= 2
        bit, fractional_part = divmod(fractional_part, 1)
        fractional_bits += str(int(bit))

    # 拼接符号位、整数二进制和小数二进制
    binary_representation = sign_bit + integer_bits + fractional_bits
    decimal_representation = int(binary_representation, 2)
    return decimal_representation


# generate geo packet
def generate_geo_pkt(ethertype, srcVmx, srcId, dstVmx, dstId):
    print("generate_geo_pkt", srcVmx, srcId, dstVmx, dstId)
    geoAreaPosLat = dstId - 63
    geoAreaPosLon = float_to_custom_bin(-180 + dstVmx * 20 + (dstId - 64) * 0.4)
    disa = 0
    disb = 0
    print(geoAreaPosLon)
    pkt = Ether(type=ethertype, src=getMacByVmx(srcVmx), dst=getMacByVmx(dstVmx))
    pkt = pkt / Raw(
        load=struct.pack("!LLLLLLLLLLLLLL", 0x00000000, 0x00400000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                         0x00000000, 0x00000000, 0x00000000, 0x00000000, geoAreaPosLat, geoAreaPosLon,
                         disa << 16 | disb, 0x00000000))
    pkt.show2()
    return pkt


# generate id packet
def generate_id_pkt(ethertype, srcVmx, srcId, dstVmx, dstId):  # 从主机信息中提取参数信息
    print("generate_id_pkt", srcVmx, srcId, dstVmx, dstId)
    srcIdentity = 202271720 + srcVmx * 100000 + srcId - 64
    dstIdentity = 202271720 + dstVmx * 100000 + dstId - 64
    pkt = Ether(type=ethertype, src=getMacByVmx(srcVmx), dst=getMacByVmx(dstVmx))
    pkt = pkt / Raw(load=struct.pack("!LL", srcIdentity, dstIdentity))
    pkt.show2()
    return pkt


# generate mf packet
def generate_mf_pkt(ethertype, srcVmx, srcId, dstVmx, dstId):
    print("generate_mf_pkt", srcVmx, srcId, dstVmx, dstId)
    srcMF = 1 + srcVmx * 1000 + srcId - 64
    dstMF = 1 + dstVmx * 1000 + dstId - 64
    pkt = Ether(type=ethertype, src=getMacByVmx(srcVmx), dst=getMacByVmx(dstVmx))
    pkt = pkt / Raw(load=struct.pack("!LLL", 0x0000001, srcMF, dstMF))
    pkt.show2()
    return pkt


# generate ndn packet
def generate_ndn_pkt(ethertype, srcVmx, srcId, dstVmx, dstId):
    print("generate_ndn_pkt", srcVmx, srcId, dstVmx, dstId)
    name_component_src = 202271720 + srcVmx * 100000 + srcId - 64
    name_component_dst = 202271720 + dstVmx * 100000 + dstId - 64
    content = 2048 + srcVmx * 1000 + srcId - 64
    print(name_component_dst, content)
    pkt = Ether(type=ethertype, src=getMacByVmx(srcVmx), dst=getMacByVmx(dstVmx))
    pkt = pkt / Raw(load=struct.pack("!LLLLLLLLL", 0x6fd0020, 0x80c0804, name_component_src,
                                     0x08840000 | ((name_component_dst >> 16) & 0xffff)
                                     , (((name_component_dst & 0xffff)) << 16) | 0x1e00, 0x18020000, 0x19020000,0x1b020000,0x1a020000 | content))
    pkt.show2()
    return pkt


def generate_ip_pkt(ethertype, srcVmx, srcId, dstVmx, dstId):
    print("generate_ip_pkt", srcVmx, srcId, dstVmx, dstId)
    srcIP = "172.20.{}.{}".format(srcVmx + 1, srcId - 64 + 12)
    dstIP = "172.20.{}.{}".format(dstVmx + 1, dstId - 64 + 12)
    pkt = Ether(type=ethertype, src=getMacByVmx(srcVmx), dst=getMacByVmx(dstVmx)) / IP(src=srcIP, dst=dstIP) / TCP(dport=1234,sport=49152)
    pkt.show2()
    return pkt

# generate FlexIP packet

length_index = 8
length_restrained = 8
length_extendable_F0 = 16
length_extendable_F1 = 32
length_extendable_F2 = 64
length_extendable_F4 = 256

format_restrained = 0
format_extendable = 1
format_hierarchical = 2
format_multiSemantics = 3

def customFlexIP(vmx, i):
    F_restrained = vmx * 20 + i - 128
    F0 = vmx*255 + i
    F1 = vmx*255*255 + i
    F2 = vmx*255*255*255 + i
    F4 = vmx*255*255*255*255 + i
    if 144<=i<152:
        return "F0{:04X}".format(F0), length_index + length_extendable_F0, format_extendable
    elif 152<=i<160:
        return "F1{:08X}".format(F1), length_index + length_extendable_F1, format_extendable
    elif 160<=i<168:
        return "F2{:016X}".format(F2), length_index + length_extendable_F2, format_extendable
    elif 168<=i<176:
        return "F4{:064X}".format(F4), length_index + length_extendable_F4, format_extendable
    elif 176<=i<184:
        return "F6F0{:04X}F1{:08X}".format(F0, F1), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F1, format_hierarchical
    elif 184<=i<192:
        return "F6F0{:04X}F2{:016X}".format(F0, F2), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F2, format_hierarchical
    elif 192<=i<200:
        return "F6F0{:04X}F4{:064X}".format(F0, F4), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F4, format_hierarchical
    elif 200<=i<208:
        return "F6F1{:08X}F2{:016X}".format(F1, F2), length_index + length_index + length_extendable_F1 + length_index + length_extendable_F2, format_hierarchical
    elif 208<=i<216:
        return "F6F1{:08X}F4{:064X}".format(F1, F4), length_index + length_index + length_extendable_F1 + length_index + length_extendable_F4, format_hierarchical
    elif 216<=i<224:
        return "F6F2{:016X}F4{:064X}".format(F2, F4), length_index + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    elif 224<=i<232:
        return "F7F0{:04X}F1{:08X}F2{:016X}".format(F0, F1, F2), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F1 + length_index + length_extendable_F2, format_hierarchical
    elif 232<=i<240:
        return "F7F0{:04X}F1{:08X}F4{:064X}".format(F0, F1, F4), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F1 + length_index + length_extendable_F4, format_hierarchical
    elif 240<=i<248:
        return "F7F0{:04X}F2{:016X}F4{:064X}".format(F0, F2, F4), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    elif 248<=i<256:
        return "F7F1{:08X}F2{:016X}F4{:064X}".format(F1, F2, F4), length_index + length_index + length_extendable_F1 + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    return "{:02X}".format(F_restrained), length_restrained, format_restrained

def generate_flexip_pkt(ethertype, srcVmx, srcId, dstVmx, dstId):
    srcFlexIP, srcLength, srcFormat = customFlexIP(srcVmx, srcId)
    print("srcFlexIP:, srcLength:, srcFormat", srcFlexIP, srcLength, srcFormat)
    dstFlexIP, dstLength, dstFormat = customFlexIP(dstVmx, dstId)
    print("dstFlexIP:, dstLength:, dstFormat", dstFlexIP, dstLength, dstFormat)
    flexip_prefix = dstLength + (srcLength << 12) + (dstFormat << 24) + (srcFormat << 26)
    print("flexip_prefix:", flexip_prefix)
    src = []
    for i in range(0, len(srcFlexIP), 8):
        substring = ""
        if i+8 <= len(srcFlexIP):
            substring = srcFlexIP[i:i+8]
        else:
            substring = srcFlexIP[i:]
            for j in range(0, i+8-len(srcFlexIP)):
                substring += '0'
        print("substring", substring)
        try:
            src.append(int(substring, 16))
        except ValueError:
            print(f"Invalid hexadecimal substring: {substring}")
    dst = []
    for i in range(0, len(dstFlexIP), 8):
        substring = ""
        if i+8 <= len(dstFlexIP):
            substring = dstFlexIP[i:i+8]
        else:
            substring = dstFlexIP[i:]
            for j in range(0, i+8-len(dstFlexIP)):
                substring += '0'
        print("substring", substring)
        try:
            dst.append(int(substring, 16))
        except ValueError:
            print(f"Invalid hexadecimal substring: {substring}")
    src += [0] * (12 - len(src))
    dst += [0] * (12 - len(dst))
    print("srcFlexIP:{}, dstFlexIP:{}, flexip_prefix", srcFlexIP, dstFlexIP, flexip_prefix)
    pkt = Ether(type=ethertype, src=getMacByVmx(srcVmx), dst=getMacByVmx(dstVmx))
    # pkt = pkt / Raw(load=struct.pack("!LLLLLLLLLLLLLLLLLLLLLLLLL", flexip_prefix, *src[:12], *dst[:12]))
    hex_string = hex(flexip_prefix)[2:10].zfill(8) + srcFlexIP.zfill(96) + dstFlexIP.zfill(96)
    print("hex_string:", hex_string)
    raw_data = bytes.fromhex(hex_string)
    pkt = pkt / Raw(load=raw_data)
    pkt.show2()
    return pkt

def getFileInfo(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
        if lines:
            last_line = lines[-1].strip()
            line_count = len(lines)
            return last_line.split(), line_count
        else:
            return [], 0

def main():
    # 检查参数数量是否正确
    if len(sys.argv) != 5:
        print('Usage: <modal_type> <frequency> <source_host> <destination_host>')
        exit(1)

    modal_type = sys.argv[1]
    frequency = int(sys.argv[2])
    source_host = int(sys.argv[3][1:])
    destination_host = int(sys.argv[4][1:])

    print("modal_type:%s, frequency:%d, source_host:%s, destination_host:%s" % (modal_type, frequency, source_host, destination_host))

    # 下发流表
    # message = f"{modal_type},{source_host},{destination_host}\n"
    # with open('flows.out', 'a') as file:
    #     file.write(message)
    # time.sleep(0.8)

    srcVmx = math.floor(source_host / 256)
    srcId = (source_host - 1) % 255 + 1
    dstVmx = math.floor(destination_host / 256)
    dstId = (destination_host - 1) % 255 + 1

    # 生成数据包
    if modal_type == "geo":
        pkt = generate_geo_pkt(geo_ethertype, srcVmx, srcId, dstVmx, dstId)
    elif modal_type == "id":
        pkt = generate_id_pkt(id_ethertype, srcVmx, srcId, dstVmx, dstId)
    elif modal_type == "mf":
        pkt = generate_mf_pkt(mf_ethertype, srcVmx, srcId, dstVmx, dstId)
    elif modal_type == "ndn":
        pkt = generate_ndn_pkt(ndn_ethertype, srcVmx, srcId, dstVmx, dstId)
    elif modal_type == "ipv4":
        pkt = generate_ip_pkt(ip_ethertype, srcVmx, srcId, dstVmx, dstId)
    elif modal_type == "flexip":
        pkt = generate_flexip_pkt(flexip_ethertype, srcVmx, srcId, dstVmx, dstId)
    else:
        print("Invalid modal type")
        exit(1)
    # get the interface
    iface = get_if()
    # print the interface and parameters
    print("sending on interface %s form %s to %s, model : %s " % (iface, source_host, destination_host, modal_type))
        
    # print("消息生产中...")
    # try:
    #   producer.send('multimodel', json.dumps(message).encode('utf-8'))
    #   print(f"Message published to kafka: {message}")
    # except Exception as e:
    #   print(f"Error on publishing message: {e}")
    # producer.flush()
    
    # 发送数据包
    for i in range (1, frequency+1):
        line_before, cnt_before = getFileInfo("/home/onos/Desktop/ngsdn/mininet/flows.out")
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.5)
        line_after, cnt_after = getFileInfo("/home/onos/Desktop/ngsdn/mininet/flows.out")
        print(line_before, cnt_before, line_after, cnt_after)
        if cnt_after == cnt_before + 1:
            print(line_after[0], line_after[1], line_after[2], modal_type, source_host, destination_host)
            if line_after[0] == modal_type and int(line_after[1]) == source_host and int(line_after[2]) == destination_host:
                print("resend!")
                sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

