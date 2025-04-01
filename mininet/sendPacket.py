# -*- coding: utf-8 -*-
import psutil
import subprocess
import requests
import time
import json
import sys
from requests.auth import HTTPBasicAuth

def getPID(source_host):
    target_string = "mininet:" + source_host
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            # 检查进程的命令行参数是否包含目标字符串
            # print("check proc cmd :{}".format(proc.info["cmdline"]))
            if proc.info['cmdline'] and any(target_string in arg for arg in proc.info['cmdline']):
                print("pid={},name={},cmd={}".format(proc.info['pid'],proc.info['name'],proc.info['cmdline']))
                return proc.info['pid']  # 返回进程号
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None  # 如果未找到进程，返回 None

def sendPacket(modal_type, source_host, destination_host):
    # 找到进程号
    pid = getPID(source_host)
    if pid is None:
        print("未找到 {} 的进程".format(source_host))
        return

    # 构造发包命令
    command = ["mnexec", "-a", str(pid), "nsenter", "-t", str(pid), "-n" ,"python3", "send.py", modal_type, "1", source_host, destination_host]
    print("执行命令:{}".format(command))

    # 子进程执行发包命令
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # 获取输出和错误
    stdout, stderr = process.communicate()

    # 输出结果
    print("标准输出: {}".format(stdout))
    #print("标准错误: {}".format(stderr))
    #print("命令退出状态码: {}".format(process.returncode))

def postSendInfo(modal_type, source_host, destination_host):
    timestamp = int(time.time())
    data = {
        "datetime": timestamp,
        "src_host": int(source_host[1:]),
        "dst_host": int(destination_host[1:]),
        "mode_name": modal_type
    }
    print(data)
    url = "http://218.199.84.172:8188/api/traffic"

    try:
        headers = {
            "Content-Type": "application/json",
        }
        json_data = json.dumps(data)
        response = requests.post(url, json_data,headers=headers,auth=HTTPBasicAuth("onos", "rocks"))

        print("POST 请求响应:{}".format(response))
    except requests.exceptions.RequestException as e:
        print("POST 请求失败:", e)

def main():
    # 检查参数数量是否正确
    if len(sys.argv) != 5:
        print('Usage: <modal_type> <frequency> <source_host> <destination_host>')
        exit(1)

    modal_type = sys.argv[1]
    frequency = int(sys.argv[2])
    source_host = sys.argv[3]  # 保持为字符串
    destination_host = sys.argv[4]  # 保持为字符串

    for i in range(frequency):
        sendPacket(modal_type, source_host, destination_host)
        postSendInfo(modal_type, source_host, destination_host)
        time.sleep(1)

    print("成功发送 {} 个数据包".format(frequency))

if __name__ == "__main__":
    main()
