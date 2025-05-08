import json
import os

# 拓扑所需的devices和links信息
devices = {}
links = {}

def get_level(i):
    if i == 1:
        return "level1"
    elif i in [2, 3]:
        return "level2"
    elif 4 <= i <= 7:
        return "level3"
    elif 8 <= i <= 15:
        return "level4"
    elif 16 <= i <= 31:
        return "level5"
    elif 32 <= i <= 63:
        return "level6"
    elif 64 <= i <= 127:
        return "level7"
    else:
        return "level8"

def get_group(i):
    if i==0 or i==3 or i==5:
        return 1
    elif i==1 or i==4 or i==6:
        return 2
    else:
        return 3

##定义每一个vmx对应的IP地质前缀，vmx[i]对应t[i+1]
vmx_ip_prefix = {
    0: "10.190.96.96",
    1: "10.190.96.97",
    2: "10.190.96.98",
    3: "10.190.96.92",
    4: "10.190.96.93",
    5: "10.190.96.99",
    6: "10.190.96.94",
    7: "10.190.96.95",
}


# 循环创建domain1
for vmx in range(0,3):
    for i in range(1, 256):
        device_id = f"device:domain1:group{get_group(vmx)}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip"  # 格式化设备ID，确保它是5位数
        devices[device_id] = {
            "basic": {
                "managementAddress": f"grpc://{vmx_ip_prefix[vmx]}:{50000 + i}?device_id=1",
                "driver": "stratum-bmv2",
                "pipeconf": "org.stratumproject.IP_ID_GEO_MF_NDN_FLEXIP.bmv2"
            }
        }
    for i in range(1, 128):
        link1 = f"device:domain1:group{vmx + 1}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip/2" + "-" + f"device:domain1:group{vmx + 1}:{get_level(i*2)}:s{i*2+vmx*255}_ip_id_geo_mf_ndn_flexip/1"
        link2 = f"device:domain1:group{vmx + 1}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip/3" + "-" + f"device:domain1:group{vmx + 1}:{get_level(i*2)}:s{i*2+1+vmx*255}_ip_id_geo_mf_ndn_flexip/1"
        links[link1] = {
            "basic": {}
        }
        links[link2] = {
            "basic": {}
        }
# 创建JSON对象
json_data = {"devices": devices, "links": links}

# 将JSON对象转换为字符串，格式化输出
json_str = json.dumps(json_data, indent=2)

# 打印JSON字符串
print(json_str)

# 可以选择将JSON字符串写入文件
with open('domain1_netcfg.json', 'w') as f:
    f.write(json_str)

devices = {}
links = {}

# 循环创建domain5
for vmx in range(3,5):
    for i in range(1, 256):
        device_id = f"device:domain5:group{get_group(vmx)}:{get_level(i)}:s{i+vmx*255}"  # 格式化设备ID，确保它是5位数
        devices[device_id] = {
            "basic": {
                "managementAddress": f"grpc://{vmx_ip_prefix[vmx]}:{50000 + i}?device_id=1",
                "driver": "stratum-bmv2",
                "pipeconf": "org.stratumproject.IP_ID_GEO_MF_NDN_FLEXIP.bmv2"
            }
        }
    for i in range(1, 128):
        link1 = f"device:domain5:group{vmx + 1}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip/2" + "-" + f"device:domain5:group{vmx + 1}:{get_level(i*2)}:s{i*2+vmx*255}_ip_id_geo_mf_ndn_flexip/1"
        link2 = f"device:domain5:group{vmx + 1}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip/3" + "-" + f"device:domain5:group{vmx + 1}:{get_level(i*2)}:s{i*2+1+vmx*255}_ip_id_geo_mf_ndn_flexip/1"
        links[link1] = {
            "basic": {}
        }
        links[link2] = {
            "basic": {}
        }

# 创建JSON对象
json_data = {"devices": devices, "links": links}

# 将JSON对象转换为字符串，格式化输出
json_str = json.dumps(json_data, indent=2)

# 打印JSON字符串
print(json_str)

# 可以选择将JSON字符串写入文件
with open('domain5_netcfg.json', 'w') as f:
    f.write(json_str)

devices = {}
links = {}

# 循环创建domain7
for vmx in range(5,8):
    for i in range(1, 256):
        device_id = f"device:domain7:group{get_group(vmx)}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip"  # 格式化设备ID，确保它是5位数
        devices[device_id] = {
            "basic": {
                "managementAddress": f"grpc://{vmx_ip_prefix[vmx]}:{50000 + i}?device_id=1",
                "driver": "stratum-bmv2",
                "pipeconf": "org.stratumproject.IP_ID_GEO_MF_NDN_FLEXIP.bmv2"
            }
        }
    for i in range(1, 128):
        link1 = f"device:domain7:group{vmx + 1}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip/2" + "-" + f"device:domain7:group{vmx + 1}:{get_level(i*2)}:s{i*2+vmx*255}_ip_id_geo_mf_ndn_flexip/1"
        link2 = f"device:domain7:group{vmx + 1}:{get_level(i)}:s{i+vmx*255}_ip_id_geo_mf_ndn_flexip/3" + "-" + f"device:domain7:group{vmx + 1}:{get_level(i*2)}:s{i*2+1+vmx*255}_ip_id_geo_mf_ndn_flexip/1"
        links[link1] = {
            "basic": {}
        }
        links[link2] = {
            "basic": {}
        }

# 创建JSON对象
json_data = {"devices": devices, "links": links}

# 将JSON对象转换为字符串，格式化输出
json_str = json.dumps(json_data, indent=2)

# 打印JSON字符串
print(json_str)

# 可以选择将JSON字符串写入文件
with open('domain7_netcfg.json', 'w') as f:
    f.write(json_str)