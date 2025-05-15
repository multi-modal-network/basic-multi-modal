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


def recvPacket(dst):
    # 找到进程号
    pid = getPID(dst)
    if pid is None:
        print("未找到 {} 的进程".format(dst))
        return
    # 构造收包,/home/kin/Desktop/baic-multi-modal-master/mininet/receive.py
    command = ["mnexec", "-a", str(pid), "nsenter", "-t", str(pid), "-n" ,"python3", "/home/kin/Desktop/baic-multi-modal-master/mininet/receive.py"]
    print("执行命令:{}".format(command))
    # 子进程执行收取命令
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # 获取输出和错误
    stdout, stderr = process.communicate()
    # 输出结果
    print("标准输出: {}".format(stdout))
    print("标准错误: {}".format(stderr))
    #print("命令退出状态码: {}".format(process.returncode))


def parse_arguments():
    parser = argparse.ArgumentParser(description='接收多模态数据包工具')

    # 必需参数
    parser.add_argument('-d', '--destination', required=True, help='目标主机')

    args = parser.parse_args()

    print(args)

    return {
        'destination_host': args.destination,
    }

def main():
    kwargs = parse_arguments()
    recvPacket(dst=kwargs["destination_host"])

if __name__ == "__main__":
    main()
