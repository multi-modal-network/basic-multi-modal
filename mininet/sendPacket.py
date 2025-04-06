# -*- coding: utf-8 -*-
import psutil
import subprocess
import requests
import time
import json
import sys
import argparse
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

def modifyTofinoPort(mode, tofino_pairs):
    if not tofino_pairs:  # 如果没有tofino_pairs则直接返回
        return
    url = "http://218.199.84.172:8188/api/tofino/port"
    headers = {"Content-Type": "application/json"}
    for switch, port in tofino_pairs:
        data = {
            "switch_id": switch,
            "modal_type": mode,
            "port": port
        }
        try:
            json_data = json.dumps(data)
            response = requests.post(
                url,
                json_data,
                headers=headers,
                auth=HTTPBasicAuth("onos", "rocks")
            )
            print(f"配置Tofino交换机 {switch} 端口 {port} 响应: {response}")
        except requests.exceptions.RequestException as e:
            print(f"配置Tofino交换机 {switch} 端口 {port} 失败: {e}")

def sendPacket(mode, src, dst):
    # 找到进程号
    pid = getPID(src)
    if pid is None:
        print("未找到 {} 的进程".format(src))
        return
    # 构造发包命令
    command = ["mnexec", "-a", str(pid), "nsenter", "-t", str(pid), "-n" ,"python3", "send.py", mode, "1", src, dst]
    print("执行命令:{}".format(command))
    # 子进程执行发包命令
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # 获取输出和错误
    stdout, stderr = process.communicate()
    # 输出结果
    print("标准输出: {}".format(stdout))
    #print("标准错误: {}".format(stderr))
    #print("命令退出状态码: {}".format(process.returncode))

def postSendInfo(mode, src, dst):
    timestamp = int(time.time())
    data = {
        "datetime": timestamp,
        "src_host": int(src[1:]),
        "dst_host": int(dst[1:]),
        "mode_name": mode
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

def validate_tofino_args(args):
    """验证-t和-p参数是否成对出现"""
    if args.tofino or args.port:
        if not (args.tofino and args.port):
            raise argparse.ArgumentError(None, "-t和-p必须同时使用")
        if len(args.tofino) != len(args.port):
            raise argparse.ArgumentError(None, "-t和-p参数数量不匹配")
        return list(zip(args.tofino, args.port))
    return None

def parse_arguments():
    parser = argparse.ArgumentParser(description='发送多模态数据包工具')

    # 必需参数
    parser.add_argument('-m', '--mode', required=True, help='模式类型')
    parser.add_argument('-n', '--frequency', type=int, required=True, help='发包数量')
    parser.add_argument('-s', '--source', required=True, help='源主机')
    parser.add_argument('-d', '--destination', required=True, help='目标主机')

    # 可选参数
    parser.add_argument('-t', '--tofino', action='append', type=int, help='Tofino交换机ID')
    parser.add_argument('-p', '--port', action='append', type=int, help='Tofino交换机端口')

    args = parser.parse_args()

    # 验证-t和-p参数
    try:
        tofino_pairs = validate_tofino_args(args)
    except argparse.ArgumentError as e:
        parser.error(str(e))

    print(args)

    return {
        'modal_type': args.mode,
        'frequency': args.frequency,
        'source_host': args.source,
        'destination_host': args.destination,
        'tofino_pairs': tofino_pairs
    }

def main():
    kwargs = parse_arguments()

    modifyTofinoPort(mode=kwargs["modal_type"], tofino_pairs=kwargs["tofino_pairs"])

    for i in range(kwargs["frequency"]):
        sendPacket(mode=kwargs["modal_type"], src=kwargs["source_host"], dst=kwargs["destination_host"])
        postSendInfo(mode=kwargs["modal_type"], src=kwargs["source_host"], dst=kwargs["destination_host"])
        time.sleep(1)

    print("成功发送 {} 个数据包".format(kwargs["frequency"]))

if __name__ == "__main__":
    main()
