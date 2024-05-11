#!/usr/bin/env python
# -*- coding: utf-8 -*-
# /usr/bin/python
# Description:           服务器信息上报龙潭
# Filename:              reportServerInfo.py
# Revision:              9.4
# Date:                  2023/11/23
# Author:                liuguohui1
# Usage:                 python reportServerInfo.py -k <static_key(选填)> -c <client_id选填> -n <api_name选填>
#                        -i <task_id选填> -m <mode选填> -b <CALLBACK选填>
# 引入python模块
import base64
import commands
import hashlib
import hmac
import json
import subprocess
import time
import datetime
import traceback
import urllib2
import re
import logging
import os
import argparse
from threading import Thread
from urllib import urlencode, quote, quote_plus

import requests

# 日志目录
LOG_DIR = "/data/script/system/logs"


# 定义写日志模块
def write_log(msg, stdout=False):
    if msg:
        logger = logging.getLogger(__name__)
        logger.setLevel(level=logging.INFO)
        dt = datetime.datetime.now()
        today = dt.strftime('%Y-%m-%d')
        if not os.path.exists(LOG_DIR):
            try:
                os.makedirs(LOG_DIR)
                write_log("创建目录成功:%s" % LOG_DIR)
            except:
                print("目录已经存在")
                write_log("目录已经存在:%s" % LOG_DIR)
        handler = logging.FileHandler(LOG_DIR + '/script.' + today + '.log')
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s	 %(levelname)s %(filename)s[line:%(lineno)d]  %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info(msg)
        if stdout:
            print(msg)
        # 删除文件句柄
        logger.removeHandler(handler)


# 定义所函数
def check_lock():
    filename = "/tmp/lockfile/reportServerInfo.lock"
    Lock_Dir = "/tmp/lockfile"
    # 判断dir是否存在
    if not os.path.exists(Lock_Dir):
        try:
            os.mkdir(Lock_Dir)
            write_log("创建目录成功")
        except:
            print("锁目录已经存在")
            write_log("目录已经存在")
    if os.path.isfile(filename):
        # 文件已经存在
        print("锁文件已经存在")
        write_log("锁文件已经存在")
        exit(-1)
    else:
        try:
            os.mknod(filename)
            write_log("锁文件创建成功")
        except:
            print("锁文件已经存在或创建失败")
            write_log("ERROR：锁文件已经存在或创建失败")
            exit(-1)


# 释放锁文件
def delete_lock():
    filename = "/tmp/lockfile/reportServerInfo.lock"
    if os.path.isfile(filename):
        # 文件已经存在
        write_log("删除锁文件")
        try:
            os.remove(filename)
            write_log("删除锁文件成功")
        except:
            write_log("删除锁文件error")


check_lock()

class TimeoutException(Exception):
    pass


ThreadStop = Thread._Thread__stop


def time_out_litmited(timeout):
    def decorator(function):
        def decorator2(*args, **kwargs):
            class TimeLimited(Thread):
                def __init__(self, _error=None, ):
                    Thread.__init__(self)
                    self._error = _error

                def run(self):
                    try:
                        self.result = function(*args, **kwargs)
                    except Exception as e:
                        self._error = str(e)

                def _stop(self):
                    if self.is_alive():
                        ThreadStop(self)

            t = TimeLimited()
            t.start()
            t.join(timeout)

            if isinstance(t._error, TimeoutException):
                t._stop()
                return

            if t.is_alive():
                t._stop()
                return

            if t._error is None:
                return t.result

        return decorator2

    return decorator


# 增加命令判断函数,type 0,默认0 退出，1 继续
@time_out_litmited(10)
def check_command(cmd, type=0):
    try:
        val = commands.getstatusoutput(cmd)
        if val[0] == 0:
            return val[1]
        else:
            if type == 0:
                print("执行命令:%s error " % (cmd))
                write_log("执行命令:%s error " % (cmd))
                delete_lock()
                exit(-1)
            else:
                return 0
    except:
        if type == 0:
            print("cmd:%s error  " % (cmd))
            write_log("cmd:%s error " % (cmd))
            delete_lock()
            exit(-1)
        else:
            return 0


def get_pdisks(vdisk_id):
    pdisk_id_pattern = re.compile('^ID\s+:\s+(?P<pdisk_id>\d+\:\d+\:\d+)')
    pdisk_size_pattern = re.compile('^Capacity\s+:\s+(?P<pdisk_size>\d+\.\d+)\s+\S+')
    pdisk_status_pattern = re.compile('^Status\s+:\s+(?P<pdisk_status>\S+)')
    pdisk_sn_pattern = re.compile('^Serial No\.\s+:\s+(?P<pdisk_sn>\S+)')
    pdisk_output = str(check_command(cmd="omreport storage pdisk vdisk={} controller=0".format(vdisk_id), type=1)).split("\n")
    pdisks = []
    pdisk_id = None
    pdisk_size = None
    pdisk_status = None
    pdisk_sn = None
    for idx, pdisk_line in enumerate(pdisk_output):
        if idx <= 2:
            continue
        if pdisk_id and pdisk_size and pdisk_status and pdisk_sn:
            pdisk = {
                "id": pdisk_id,
                "size": pdisk_size,
                "status": pdisk_status,
                "sn": pdisk_sn
            }
            print(pdisk_id, pdisk_size, pdisk_status, pdisk_sn)
            pdisks.append(pdisk)
            pdisk_id = None
            pdisk_size = None
            pdisk_status = None
            pdisk_sn = None

        if not pdisk_id:
            pdisk_id_match = pdisk_id_pattern.match(pdisk_line)
            if pdisk_id_match:
                pdisk_id = pdisk_id_match.group("pdisk_id")
                continue
        if not pdisk_size:
            pdisk_size_match = pdisk_size_pattern.match(str(pdisk_line).replace(",", ""))
            if pdisk_size_match:
                pdisk_size = pdisk_size_match.group("pdisk_size")
                continue
        if not pdisk_status:
            pdisk_status_match = pdisk_status_pattern.match(pdisk_line)
            if pdisk_status_match:
                pdisk_status = pdisk_status_match.group("pdisk_status")
                continue
        if not pdisk_sn:
            pdisk_sn_match = pdisk_sn_pattern.match(pdisk_line)
            if pdisk_sn_match:
                pdisk_sn = pdisk_sn_match.group("pdisk_sn")
                continue
    return pdisks


def get_vdisks():
    vdisk_id_pattern = re.compile('^ID\s+:\s+(?P<vdisk_id>\d+)')
    vdisk_state_pattern = re.compile('^State\s+:\s+(?P<vdisk_state>\S+)')
    vdisk_layout_pattern = re.compile('^Layout\s+:\s+(?P<vdisk_layout>\S+)')
    vdisk_output = str(check_command(cmd="omreport storage vdisk", type=1)).split("\n")
    vdisks = []
    vdisk_id = None
    vdisk_state = None
    vdisk_layout = None
    for idx, vdisk_line in enumerate(vdisk_output):
        if vdisk_id and vdisk_state and vdisk_layout:
            vdisk = {"vdisk_id": vdisk_id, "vdisk_state": vdisk_state, "pdisks": get_pdisks(vdisk_id),
                     "vdisk_layout": vdisk_layout}
            vdisks.append(vdisk)
            vdisk_id = None
            vdisk_id = None
        if idx > 2:
            if not vdisk_id:
                vdisk_id_match = vdisk_id_pattern.match(vdisk_line)
                if vdisk_id_match:
                    vdisk_id = vdisk_id_match.group('vdisk_id')
                    continue

            if not vdisk_state:
                vdisk_state_match = vdisk_state_pattern.match(vdisk_line)
                if vdisk_state_match:
                    vdisk_state = vdisk_state_match.group('vdisk_state')
                    continue
            if not vdisk_layout:
                vdisk_layout_match = vdisk_layout_pattern.match(vdisk_line)
                if vdisk_layout_match:
                    vdisk_layout = vdisk_layout_match.group('vdisk_layout')
                    continue
    return vdisks


# 获取主机管理网的ip，物理机和虚拟机通用，先用ip addr 命令获取所有ip地址，然后只要10，或192开头的ip地址，并且排除192.168.122.1这个kvm的ip
# mgmt ip
def ipaddr():
    # 判断mip
    ipaddr = check_command("/usr/local/sbin/mip")
    return ipaddr


def main(url, token, client_id, api_info, report_time):
    # import ipdb;ipdb.set_trace()
    # 管理卡信息
    # 管理卡ip
    bmc = ''
    # 管理卡mac
    bmc_mac = ''
    # 管理卡netmask
    bmc_netmask = ''
    # 管理卡网关
    bmc_gateway = ''
    # 管理卡版本
    bmc_firmware_version = ''
    # 管理卡boot模式
    bios_boot_mode = ''
    # 电源连接
    power_socket = ''
    # 初始化交换机信息 nics_switch_list
    nics_switch_list = []
    lldp_data = ''
    # 获取服务器的型号
    check_command("dmidecode -t system")
    equipment_model = check_command("dmidecode -t system|awk -F':' '/Product Name/{print$NF}'").strip()

    # 获取主机bios的版本
    bios_version_list = check_command("dmidecode|grep -A2 'BIOS Information'|grep Version").split(':')
    if len(bios_version_list) > 1:
        bios_version = bios_version_list[1]
    else:
        bios_version = ""

    # 获取主机的sn
    equipment_sn = check_command("dmidecode -t system|awk '/Serial Number/{print$NF}'")

    # 获取主机名
    server_hostname = check_command("hostname")
    p = r'(.*)(\w+\W+\w+\W+.*.liepin.inc)'
    pro = re.match(p, server_hostname, re.S | re.M | re.U)
    if pro:
        server_hostname = server_hostname
    else:
        print("get hostname error1")
        write_log("获取主机名失败")
        delete_lock()
        exit(-1)
    # 获取系统当前时间
    collectd_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 获取系统类型和系统版本
    server_os = check_command("cat /etc/redhat-release")

    # 获取系统内核版本
    server_kernel = check_command("uname -r")

    # server cpu info
    # 获取主机cpu的品牌，型号，主频
    server_cpu_model_name = check_command("cat /proc/cpuinfo|awk -F':' '/model name/{print$NF}'|sort|uniq").strip()

    # 获取cpu的核数（包括超线程之后的）
    server_cpu_num = check_command("cat /proc/cpuinfo|grep processor|wc -l")

    # cpu型号和核数的组合显示
    server_cpu_desc = "%s * %s" % (server_cpu_model_name, server_cpu_num)

    # 获取cpu的颗数
    check_command("lscpu")
    server_cpu_socket = commands.getoutput("lscpu|awk '/^Socket/{print$2}'|grep -Eo '[0-9]+'")
    # 增加判断，如果大于0就转为整型
    if len(server_cpu_socket) > 0:
        server_cpu_socket = int(server_cpu_socket)
    else:
        # 添加中文判断
        server_cpu_socket = commands.getoutput("lscpu|awk '/^座/{print$2}'|grep -Eo '[0-9]+'")
        if len(server_cpu_socket) > 0:
            server_cpu_socket = int(server_cpu_socket)
        else:
            print("get server_cpu_socket error")
            write_log("get server_cpu_socket error :")
            delete_lock()
            exit(-1)
    # 判断cpu是否开启了超线程
    threads_per_core = check_command("lscpu|awk '/Thread.* per core/{print$NF}'")
    if threads_per_core == '1':
        cpu_hyper_thread = '0'
    else:
        cpu_hyper_thread = '1'

    # 主机的默认网关
    check_command("route -n")
    ip_gateway = check_command("route -n|awk '/^0.0.0.0/{print$2}'")

    # 获取cpu类型，后面会根据cpu类型来判断是物理机，还是虚拟机。物理机和虚拟机采集数据的方式不同
    cpu_type = check_command("cat /proc/cpuinfo|awk  '/model name/{print$4}'|sort|uniq")

    # 获取raid版本信息
    def get_raid_version():
        raid_info = {}
        if ('R740' in equipment_model) or ('X640 G40' in equipment_model) or ('R750' in equipment_model) or (not os.path.exists("/usr/local/sbin/MegaCli/MegaCli")):
            raid_name = str(check_command(cmd="omreport storage controller |grep Name|awk -F':' '{print $2}'", type=1)).strip()
            firmware_version = str(check_command(
                cmd="omreport storage controller |grep -E '^Firmware Version'|awk -F':' '{print $2}'", type=1)).strip()
        else:
            raid_name = str(check_command(
                cmd="/usr/local/sbin/MegaCli/MegaCli -AdpAllInfo -aALL -NoLog |grep 'Product Name'|awk -F':' '{print $2}'", type=1)).strip()
            firmware_version = str(check_command(
                cmd="/usr/local/sbin/MegaCli/MegaCli -AdpAllInfo -aALL -NoLog|grep 'FW Package Build'|awk -F':' '{print $2}'", type=1)).strip()

        raid_info = {"raid_name": raid_name, "firmware_version": firmware_version}

        return raid_info

    # 对于megacli不能使用的机器和虚拟机，获取磁盘信息
    # 硬盘信息，通过fdisk命令获取
    def fdisk_info():
        diskinfo_list = []
        # disk_size1 = commands.getoutput("fdisk -l /dev/*da|awk '/GB/{print$3}'")
        # disk_size = re.findall("\d+", disk_size1, re.MULTILINE)[0]
        check_command("fdisk -l")
        disk_size = check_command("fdisk -l /dev/*da|awk '/GB/{print$3}'|awk -F'.' '{print $1}'")
        # 加上是否中文显示
        if 'GB' in disk_size:
            disk_size = check_command(
                "fdisk -l /dev/*da|awk  '/GB/{print$2$3}'|awk -F'：' '{print $2}'|awk -F'.' '{print $1}'")
        if 'WARNING' in disk_size:
            disk_size = disk_size.split('\n')[1]
        diskinfo_list = [
            {"card_id": str(0), "dg_raid_type": "", "dg_raid_state": "", "dg_id": str(0), "dg_size": disk_size,
             "arr_raid_state": "", "arr_id": str(0), "row_id": str(0), "disk_id": str(0), "disk_slot": "",
             "disk_size": disk_size, "disk_status": "Online", "disk_desc": disk_size, "disk_model": "Is vm disk"}]
        return diskinfo_list

    # 利用MegaCli统一获取，去除omreport 获取raid信息，和磁盘信息，磁盘大小，序列表和描述
    def raid_cards():
        # 初始化变量
        n = 0
        dg_raid_state = ''
        disk_state = ''
        dg_raid_type = ''
        dg_id = '0'
        card_id = '0'
        dg_raid_state = ''
        disk_slot = ''
        disk_id = ''
        disk_desc = ''
        disk_model = ''
        disk_size = ''
        diskinfo_list = []
        if 'R310' in equipment_model:
            diskinfo_list = fdisk_info()
            return diskinfo_list
        if 'X640 G40' in equipment_model:
            # 宁畅机器无法获取vdisk
            return []
        if ('R740' in equipment_model) or ('R750' in equipment_model) or (not os.path.exists("/usr/local/sbin/MegaCli/MegaCli")):
            vdisk_list = get_vdisks()
            for vdisk in vdisk_list:
                dg_raid_type = vdisk["vdisk_layout"]
                dg_raid_state = vdisk["vdisk_state"]
                for pdisk in vdisk["pdisks"]:
                    disk_slot = pdisk["id"]
                    disk_size = pdisk["size"]
                    disk_status = pdisk["status"]
                    disk_model = pdisk["sn"]
                    diskinfo = {
                        "card_id": card_id,
                        "dg_raid_type": dg_raid_type,
                        "dg_raid_state": dg_raid_state,
                        "dg_id": dg_id,
                        "disk_id": disk_id,
                        "disk_slot": disk_slot,
                        "disk_size": disk_size,
                        "disk_status": disk_status,
                        "disk_desc": disk_desc,
                        "disk_model": disk_model
                    }
                    diskinfo_list.append(diskinfo)
            return diskinfo_list
        else:
            if os.path.exists("/usr/local/sbin/MegaCli/MegaCli"):
                result = check_command(cmd="/usr/local/sbin/MegaCli/MegaCli -LdPdInfo -a0 -NoLog ", type=1)
                if result == 0:
                    return []
                results = result.split('\n')
                raid_dict = {'Primary-1, Secondary-0, RAID Level Qualifier-0': 'RAID-1',
                             'Primary-0, Secondary-0, RAID Level Qualifier-0': 'RAID-0',
                             'Primary-5, Secondary-0, RAID Level Qualifier-3': 'RAID-5',
                             'Primary-6, Secondary-0, RAID Level Qualifier-3': 'RAID-6',
                             'Primary-1, Secondary-3, RAID Level Qualifier-0': 'RAID-10'}
                # 获取磁盘状态信息
                disk_states = re.findall("Firmware state:\s+(\w+)", result, re.MULTILINE)
                # 获取磁盘型号
                disk_models = re.findall("WWN:\s+(\w+)", result, re.MULTILINE)
                # 磁盘描述信息
                disk_descs = re.findall("Inquiry Data:\s+(.*)", result, re.MULTILINE)
                # 磁盘size信息
                disk_sizes = re.findall("Raw Size:\s+(\d+\W+\d+\s+\w+)", result, re.MULTILINE)
                # 循环遍历raid磁盘信息
                for i in results:
                    raidn = re.findall("Virtual Drive:\s+(\d+)", i, re.MULTILINE)
                    rlevel = re.findall("RAID Level\s+:\s+(\w+\W+\w+,\s+\w+\W+\w+,\s+\w+\s+\w+\s+\w+\W+\w+)", i,
                                        re.MULTILINE)
                    dg_raid_states = re.findall("State\s+:\s+(\w+)", i, re.MULTILINE)
                    disk = re.findall("Slot Number:\s+(\d+)", i, re.MULTILINE)
                    if n < len(disk_descs):
                        disk_desc = disk_descs[n].strip()
                    if n < len(disk_states):
                        disk_state = disk_states[n]
                    if dg_raid_states:
                        dg_raid_state = dg_raid_states[0]
                    if n < len(disk_models):
                        disk_model = disk_models[n]
                    if n < len(disk_sizes):
                        disk_info = disk_sizes[n]
                        # 如果是TB的需要转换为GB
                        if 'TB' in disk_info:
                            disks = re.findall("(\d+\W+\d+)", disk_info, re.MULTILINE)
                            disk_size = float(disks[0]) * 1024
                        else:
                            disks = re.findall("(\d+\W+\d+)", disk_info, re.MULTILINE)
                            disk_size = disks[0]
                    disk_slot = '0:1:' + str(n)
                    if raidn:
                        r = int(raidn[0])
                    if rlevel:
                        dg_raid_type = raid_dict[rlevel[0]]
                    if disk and disk_size:
                        card_id = disk[0]
                        arr_id = disk[0]
                        dg_id = disk[0]
                        disk_id = str(disk[0])
                        disk_size = str(disk_size)
                        disk_slot = '0:1:' + str(disk[0])
                        diskinfo_list.append(
                            {"card_id": card_id, "dg_raid_type": dg_raid_type, "dg_raid_state": dg_raid_state,
                             "dg_id": dg_id, "dg_size": disk_size, "arr_raid_state": disk_state,
                             "arr_id": arr_id, "row_id": disk_id, "disk_id": disk_id, "disk_slot": disk_slot,
                             "disk_size": disk_size, "disk_status": disk_state, "disk_desc": disk_desc,
                             "disk_model": disk_model})
                        n += 1
                return diskinfo_list
            else:
                return []

    # 利用ipmi获取bmc
    def get_ipmi_bmc():
        # dell工具获取失败后，用ipmitool获取,获取不到继续，只是返回为空
        bmcinfo = check_command("/usr/bin/ipmitool lan print", 1)
        write_log("/usr/bin/ipmitool lan print")
        write_log(bmcinfo)
        if bmcinfo:
            bmc_mac = re.findall("MAC Address\s+\:\s+(.*)", bmcinfo, re.MULTILINE)[0].replace('-', ':').lower()
            bmc_netmask = re.findall("Subnet Mask\s+\:\s+(.*)", bmcinfo, re.MULTILINE)[0]
            bmc_gateway = re.findall("Default Gateway IP\s+\:\s+(.*)", bmcinfo, re.MULTILINE)[0]
            bmc = re.findall("IP Address\s+\:\s+(.*)", bmcinfo, re.MULTILINE)[0]
            return (bmc_mac, bmc_netmask, bmc_gateway, bmc)
        else:
            return 0

    host_type_distinguish = check_command("lscpu | grep Virtualization | awk '{print $NF}'")
    # 以下是对物理机采集数据
    # Physical host info
    # if cpu_type == 'Intel(R)' and 'Alibaba' not in equipment_model:
    if host_type_distinguish == 'VT-x' or 'R420' in equipment_model:

        # 是否是虚拟机，0是否
        server_virtual = '0'
        # 是否有远程管理卡，物理机默认都有，虚拟机都没有
        server_remote_card = '1'
        # 判断物理机中是否是DELL的服务器
        # is dell or is not dell
        # server_manufacturer = commands.getoutput("dmidecode -t system|grep -io dell").lower()
        server_manufacturer = commands.getoutput("dmidecode -t system|grep -i manufacturer|grep -i 'dell'")
        # 如果是DELL服务器，就支持omreport命令，以下是用omreport命令来获取一些参数
        if 'Dell' in server_manufacturer or 'DELL' in server_manufacturer or 'dell' in server_manufacturer:
            # 获取服务器的远程管理卡的ip, mac, 掩码，网关，固件版本
            # bmc info
            bmc_info = check_command("/opt/dell/srvadmin/bin/omreport chassis bmc", 1)
            write_log("/opt/dell/srvadmin/bin/omreport chassis bmc")
            write_log(bmc_info)
            if bmc_info:
                bmc_list = re.findall("IP Address\s+\:\s+(.*)", bmc_info, re.MULTILINE)
                if len(bmc_list) > 0:
                    bmc = bmc_list[0]
                    bmc_mac = re.findall("MAC Address\s+\:\s+(.*)", bmc_info, re.MULTILINE)[0].replace('-', ':').lower()
                    bmc_netmask = re.findall("IP Subnet\s+\:\s+(.*)", bmc_info, re.MULTILINE)[0]
                    bmc_gateway = re.findall("IP Gateway\s+\:\s+(.*)", bmc_info, re.MULTILINE)[0]
                bmc_firmware_version = str(check_command(
                    cmd="/opt/dell/srvadmin/bin/omreport chassis firmware|awk '/iDRAC/{print$1\",\"$3}'", type=1))

                # bios启动模式，有BIOS和UEFI两种
                bios_boot_mode = check_command(
                    cmd="/opt/dell/srvadmin/bin/omreport chassis biossetup 2> /dev/null|awk '/^Boot Mode/{print$4}'", type=1)

                # 电源插槽
                power_socket = str(check_command(
                    cmd="/opt/dell/srvadmin/bin/omreport chassis pwrsupplies|awk '/^Index/{print$NF}'", type=1)).replace('\n', ',')
            else:
                bmcinfo = get_ipmi_bmc()
                if bmcinfo:
                    # (bmc_mac,bmc_netmask,bmc_gateway,bmc)
                    bmc_mac = bmcinfo[0]
                    bmc_netmask = bmcinfo[1]
                    bmc_gateway = bmcinfo[2]
                    bmc = bmcinfo[3]

        # 如果不是dell服务器，用ipmitool获取
        else:
            bmcinfo = get_ipmi_bmc()
            if bmcinfo:
                # (bmc_mac,bmc_netmask,bmc_gateway,bmc)
                bmc_mac = bmcinfo[0]
                bmc_netmask = bmcinfo[1]
                bmc_gateway = bmcinfo[2]
                bmc = bmcinfo[3]
            # bmc = check_command("/usr/bin/ipmitool lan print|awk '/IP Address\ +\:/{print$NF}'")
            print(bmc)

        # 获取网卡连接的交换机的名字，端口号，vlan号，具体步骤如下：
        # 1，判断lldpd服务有没有启动
        # 2，如果没有启动，就更新系统的yum仓库，判断lldpd的包是否安装
        # 3，如果没有安装，就安装lldpd包
        # 4，启动lldpd服务，由于lldpd服务启动要1到5秒，在启动服务之后让脚本等待6秒，再用lldpctl命令采集交换机信息
        # lldpctl info
        # 获取交换机信息，并以key vlule的形式存到变量lldp_data中。连交换机的端口，以列表形式存到nics_switch_list中，这2个变量会被下面的ips()函数使用
        # used by ips()，如果命令有问题，继续往下执行，但是内容为空
        lldp_data = check_command('lldpctl -f keyvalue', 1)
        nics_switch_list = check_command("lldpctl |awk '/^Interface/{printf$2}'", 1).rstrip(',').split(',')

        # 获取内存信nics_switch_list息，每条内存都会通过循环附加到mem_list列表中。内存信息有槽位，大小，描述（频率和制造商id）
        def mem():
            data = ""
            mem_list = []
            memory = check_command("dmidecode -t memory")
            MEM_N = re.findall("Memory Device(.*?\n\n|.*?\n\Z)", memory, re.S)
            for i in range(0, len(MEM_N)):
                MEM_SIZE = re.findall("^[\s]*Size:.*", MEM_N[i], re.MULTILINE)
                MEM_LOC = re.findall("^[\s]*Locator:.*", MEM_N[i], re.MULTILINE)
                MEM_SPEED = re.findall("^[\s]*Speed:.*", MEM_N[i], re.MULTILINE)
                MEM_Manufacturer = re.findall("^[\s]*Manufacturer:.*", MEM_N[i], re.MULTILINE)
                if len(re.findall("\d+", MEM_SIZE[0])) > 0:
                    data += MEM_SIZE[0].split(":")[1].strip() + ","
                    data += MEM_LOC[0].split(":")[1].strip() + ","
                    data += MEM_SPEED[0].split(":")[1].strip() + ","
                    data += MEM_Manufacturer[0].split(":")[1].strip() + ";"
            # print data.rstrip(";")
            # print len(data.rstrip(";").split(';'))
            mem_info = data.rstrip(";").split(';')
            # print mem_info
            if len(mem_info) > 0:
                for j in range(0, len(mem_info)):
                    # mem_size = int(mem_info[j].split('MB')[0]) / 1024
                    mem_size_list = mem_info[j].split(',')[0].split()
                    if mem_size_list[1] == 'MB':
                        mem_size = int(mem_size_list[0])
                    else:
                        mem_size = int(mem_size_list[0]) * 1024
                    slot = mem_info[j].split(',')[1]
                    memory_desc = mem_info[j].split(',')[2] + ',' + mem_info[j].split(',')[3]
                    mem_list.append({"slot": slot, "memory": mem_size, "memory_desc": memory_desc})
            return mem_list

        # 获取raid卡信息，有名字，状态，当前固件版本，需要的最小固件版本。如果不是DELL的服务器，利用megacli 进行获取
        # raid info
        def raid():
            raid_info = {}
            raid_info = get_raid_version()
            return raid_info

    # 以下是对虚拟机的采集方法
    # Virtual host info
    else:
        # 是否是虚拟机，1表示是
        server_virtual = '1'
        # 是否有远程管理卡，虚拟机默认没有，值为0
        server_remote_card = '0'

        # 如果虚拟机没有SN,则使用UUID。其中SN的要求上报要求最少为4位，世纪互联虚拟主机中SN获取只有2位，故添加4位长度条件
        if equipment_sn == "Specified" or len(equipment_sn) < 4:
            equipment_sn = check_command("dmidecode -t system|awk '/UUID/{print$NF}'")

        # 硬盘信息，通过fdisk命令获取
        def raid_cards():
            diskinfo_list = fdisk_info()
            return diskinfo_list

        # 获取内存信息，通过dmidecode获取，内存的默认单位是MiB,
        def mem():
            mem_size = check_command("dmidecode -t memory|awk '/Maximum Capacity/{print$3}'")
            mem_list = [{"slot": "0", "memory": int(mem_size) * 1024, "memory_desc": "Is vm memory"}]
            return mem_list

        # 虚拟机没有raid卡信息，直接返回空字典
        def raid():
            raid_info = {}
            return raid_info

    # 获取ip信息，物理机和虚拟机通用
    def ips():
        # 把bond_have, bond两个变量设置为全局，会被bindings()函数使用
        global bond_have, bond

        # 子网掩码的转换，短格式转换为长格式，如: 24 -> 255.255.255.0
        # exchange netmask short to long
        def exchange_maskint(mask_int):
            bin_arr = ['0' for i in range(32)]
            for i in range(mask_int):
                bin_arr[i] = '1'
            tmpmask = [''.join(bin_arr[i * 8:i * 8 + 8]) for i in range(4)]
            tmpmask = [str(int(tmpstr, 2)) for tmpstr in tmpmask]
            return '.'.join(tmpmask)

        # 获取主机上所有的网卡名字，包括状态为up和down的。但只要e开头的，如em,eth,ens等
        ips_list = []
        # nics = commands.getoutput("ifconfig -a|awk '/^e|^bond/{print$1}'|sed 's/:$//p'|sort|uniq")
        check_command("ip a")
        nics = check_command(
            "ip a show |awk '{print $2}'|awk '/^eth|^em|^en|^bond/{print$1}'|sed 's/:$//p'|sort|uniq|grep -v ':'")
        nics_list = nics.split()
        # 判断是否有bond，如果有，把bond的网卡附加到网卡列表中
        # bond = commands.getoutput("ip a|grep -o 'bond0'|sort|uniq")
        # if bond == 'bond0':
        #    bond_have = '1'
        #    nics_list.append(bond)
        # else:
        #    bond_have = '0'
        # 去除重复网卡列表
        # nics_list=list(set(nics_list))
        nics_list = sorted(nics_list)
        bond = nics_list
        # 判断是否有br或brv开头的网卡，如果有，以列表的形式加入到nics_list中
        brs = check_command("ip a|egrep -o '\<br[0-9]+|\<brv[0-9]+'|sort|uniq")
        if len(brs) > 0:
            brs_list = brs.split('\n')
            nics_list += brs_list
        # 如果有网卡，通过循环获取每个网卡的速率，IP（可能有很多），mac
        if len(nics_list) > 0:
            for i in range(0, len(nics_list)):
                nic = nics_list[i]
                # 如果网卡为bond0.73@bond0需要截取@前边，避免获取异常
                if '@' in nic:
                    nic = nic.split('@')[0]
                nic_info = check_command("ip a show %s" % (nic))
                nic_mac_list = re.findall("\w+\:\w+\:\w+\:\w+\:\w+\:\w+", nic_info, re.MULTILINE)
                if len(nic_mac_list) > 0:
                    nic_mac = nic_mac_list[0]
                else:
                    nic_mac = ''
                nic_speed = ''
                # 如果网卡包含":"或'.' 属于网卡别名，不再获取网卡速率
                if ':' not in nics_list[i] and '.' not in nics_list[i]:
                    nic_speed = check_command("ethtool %s|awk '/Speed/{print$2}'" % nics_list[i])
                nic_ips = re.findall("(\d+\.\d+\.\d+\.\d+)\/\d+", nic_info, re.MULTILINE)
                nic_netmasks = re.findall("\d+\.\d+\.\d+\.\d+\/(\d+)", nic_info, re.MULTILINE)

                # 获取每个网卡的所有ip.掩码为255.255.255.255的是vip，生成ip列表
                def network_mac_ips():
                    vipflag = 0
                    mac_ips_list = []
                    if len(nic_ips) > 0:
                        for j in range(0, len(nic_ips)):
                            ipaddress = nic_ips[j]
                            netmask_short = int(nic_netmasks[j])
                            netmask = exchange_maskint(netmask_short)
                            if '255.255.255.255' in netmask:
                                vipflag = 1
                            mac_ips_list.append({"ip": ipaddress, "netmask": netmask, "vipflag": str(vipflag),
                                                 "ip_gateway": ip_gateway})
                    return mac_ips_list

                # 获取连接交换机的网卡，并于系统的所有网卡比较，如果相等，就获取这个网卡连接交换机的交换机名字，端口号，vlan号
                def network_mac_switch():
                    network_mac_switch_dict = {}
                    # switch_hostname = ''
                    # nic_to_switch_port = ''
                    # sp_port_vlan = ''
                    if cpu_type == 'Intel(R)':
                        if len(nics_switch_list) > 0:
                            for k in range(0, len(nics_switch_list)):
                                if nics_list[i] == nics_switch_list[k]:
                                    try:
                                        switch_hostname = re.findall('lldp\.%s\.chassis\.name=([^_]+(?:_[^_]+){'
                                                                     '3}_\d+\.\d+)' % (nics_switch_list[k]),
                                                                     lldp_data)[0]
                                        nic_to_switch_port = \
                                        re.findall('lldp\.%s\.port\.ifname=(.*)' % (nics_switch_list[k]), lldp_data)[0]
                                        sp_port_vlan = \
                                        re.findall("lldp\.%s\.vlan\.vlan-id=(.*)" % (nics_switch_list[k]), lldp_data)[0]
                                        network_mac_switch_dict = {"switch_hostname": switch_hostname,
                                                                   "sp_port": nic_to_switch_port,
                                                                   "sp_port_vlan": sp_port_vlan}
                                    except:
                                        ### 返回空对象的话不能直接写成None，上报龙潭会有异常，要写成{}
                                        network_mac_switch_dict = {}
                                    break
                    return network_mac_switch_dict

                ips_list.append({"slot": str(i), "network_mac": nics_list[i] + "," + nic_mac, "nic_speed": nic_speed,
                                 "network_mac_ips": network_mac_ips(), "network_mac_switch": network_mac_switch()})
        return ips_list

    # 网卡bond的信息，有bond名称，模式和做bond的网卡
    # bond info，遍历网卡列表，如果":","." 包含在网卡里属于别名，无需获取bond信息，生成bond信息字典
    def bondings(bonds):
        bond_info = {}
        for b in bonds:
            if 'bond' in b and ':' not in b and '.' not in b:
                bond_name = b
                bond_mode = check_command(
                    "cat /proc/net/bonding/%s|awk -F':' '/Bonding Mode/{print$2}'" % bond_name).strip()
                bond_nics = check_command(
                    "cat /proc/net/bonding/%s|awk '/Slave Interface/{print$3}'" % bond_name).replace('\n', ',')
                info = {"bond_name": bond_name, "bond_mode": bond_mode, "bond_nics": bond_nics}
                bond_info.update(info)
            else:
                pass
        return bond_info

    # 所有采集数据的汇总
    # DATA SUMMARY
    if bmc == '0.0.0.0' or bmc_netmask == "0.0.0.0" or bmc_gateway == "0.0.0.0":
        server_data = {"equipment_model": equipment_model, "equipment_sn": equipment_sn, "equipment_type": "1",
                       "manager_ip": ipaddr(), "server_hostname": server_hostname, "server_virtual": server_virtual,
                       "server_remote_card": server_remote_card, "bmc_mac": bmc_mac, "bmc_user": "", "bmc_passwd": "",
                       "bmc_firmware_version": bmc_firmware_version, "bios_version": bios_version,
                       "server_os": server_os, "server_kernel": server_kernel, "server_cpu_desc": server_cpu_desc,
                       "server_cpu_socket": server_cpu_socket, "bios_boot_mode": bios_boot_mode,
                       "cpu_hyper_thread": cpu_hyper_thread, "power_socket": power_socket, "network_macs": ips(),
                       "bond_info": bondings(bond), "raid_info": raid(), "memorys": mem(), "raid_cards": raid_cards()}
    else:
        server_data = {"equipment_model": equipment_model, "equipment_sn": equipment_sn, "equipment_type": "1",
                       "manager_ip": ipaddr(), "server_hostname": server_hostname, "server_virtual": server_virtual,
                       "server_remote_card": server_remote_card, "bmc": bmc, "bmc_mac": bmc_mac,
                       "bmc_netmask": bmc_netmask, "bmc_gateway": bmc_gateway, "bmc_user": "", "bmc_passwd": "",
                       "bmc_firmware_version": bmc_firmware_version, "bios_version": bios_version,
                       "server_os": server_os, "server_kernel": server_kernel, "server_cpu_desc": server_cpu_desc,
                       "server_cpu_socket": server_cpu_socket, "bios_boot_mode": bios_boot_mode,
                       "cpu_hyper_thread": cpu_hyper_thread, "power_socket": power_socket, "network_macs": ips(),
                       "bond_info": bondings(bond), "raid_info": raid(), "memorys": mem(), "raid_cards": raid_cards()}

    # 转化为json格式
    json_server_data = json.dumps(server_data)
    # print server_data
    print('---------------')
    print("{}&token={}&client_id={}&api={}&ip={}&timestamp={}".format(json_server_data, token, client_id, api_info, ipaddr(), report_time))
    print('---------------')
    # print equipment_sn
    # 通过api上报数据，并打印上报结果，循环3次，每次60秒，如果正常退出
    # upload data to api
    message_dict = {"flag": -1}
    headers = {"X-Requested-With": "XMLHttpRequest"}
    for i in range(3):
        request = urllib2.Request(url, "json={}&token={}&client_id={}&api={}&ip={}&timestamp={}".format(json_server_data, token, client_id, api_info, ipaddr(), report_time), headers)
        # print request
        response = urllib2.urlopen(request, timeout=60)
        # print response
        message = response.read()
        print(message)
        message_dict = json.loads(message)
        if message_dict['flag'] == 1:
            break
        time.sleep(5)
    # 如果没有上报成功，则脚本退出码为-1
    if message_dict['flag'] != 1:
        write_log(message_dict)
        delete_lock()
        exit(-1)
    # 删除锁文件
    delete_lock()


# ----------------------- cmdb token生成方式 --------------------------------
# 生成时间戳
def get_new_time():
    now_time = datetime.datetime.now()
    time_str = now_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    return time_str


# 获取悟空签名
def sortStringWithPost(data_dict):
    postStr = "POST&%2F&" + sortString(data_dict=data_dict)
    return postStr


def sortString(data_dict):
    data_list = []
    for key in data_dict.keys():
        data_list.append('{}={}'.format(key, data_dict[key]))
    data_list.sort()
    res = '&'.join(data_list)
    return quote_plus(res).replace(r'%20', r'+')


def getSignature(data, key):
    # mac = hmac.new(bytes(key, "utf-8"), bytes(data, "utf-8"), hashlib.sha1)
    mac = hmac.new(str(key).encode("utf-8"), str(data).encode("utf-8"), hashlib.sha1)
    value = mac.digest()
    value = base64.b64encode(value)
    return value


def get_signature(data, secret_key):
    postStr = sortStringWithPost(data_dict=data)
    write_log("获取排序后的编码参数值: {}".format(postStr))
    signature = getSignature(postStr, secret_key + "&")
    return signature


# 执行接口
def signature_info(data, secret_key, time_flag):
    data.update({"timestamp": time_flag})
    # 获取token
    sign_token = get_signature(data, secret_key)
    return sign_token


# 参数shell=False, 指明命令不以shell格式标准执行, 安全设置
def cmd_info(cmd_str, cmdTimeout=10):
    out_str = None
    proc = None
    try:
        proc = subprocess.Popen(cmd_str, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True,
                                encoding="utf-8")
        out, err = proc.communicate(timeout=cmdTimeout)
        exit_code = proc.returncode
        return out, exit_code
    except subprocess.TimeoutExpired as toe:
        write_log("{} -- {}".format("执行系统命令超时", traceback.format_exc()), stdout=True)
        return out_str, 10
    except Exception as e:
        write_log("{} -- {}".format("执行系统命令报错, {}", e.args, traceback.format_exc()), stdout=True)
        return out_str, -1
    finally:
        proc.stdout.close()
        proc.stderr.close()
        proc.kill()


# 生成token
def get_cmdb_token(secret_key, cci,  can):
    host_ip = ipaddr()
    data = {
        "ip": host_ip,
        "client_id": cci,
        "api": can
    }
    time_flag = get_new_time()
    sign_token = signature_info(data, secret_key, time_flag)
    write_log("{} get cmdb sign information {} {} {}".format(host_ip, sign_token, cci, can))
    return sign_token.decode(), data['client_id'], data['api'], time_flag


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-k', '--secret_key', help='cmdb static key')
        parser.add_argument('-c', '--client_id', help='client id')
        parser.add_argument('-n', '--api_name', help='api name')
        parser.add_argument('-i', '--task_id', help='time flag')
        parser.add_argument('-m', '--mode', help='task mode')
        parser.add_argument('-b', '--callback', help='task callback url')
        args = parser.parse_args()
        secretKey = args.secret_key
        if secretKey is None:
            secretKey = "RNcrMB34Cgarj3y822l6gQBn"
        clientId = args.client_id
        if clientId is None:
            clientId = "200000"
        apiName = args.api_name
        if apiName is None:
            apiName = "airsServerInstallKey"
        # 获取发送指令参数
        task_id = args.task_id
        cmdb_url = args.callback
        if cmdb_url is None:
            cmdb_url = 'http://longtan.tongdao.cn/BaseResourceController/reportServer.json'
        if task_id is None:
            task_id = 'init'
        # 生成token
        token, client_id, api_name, report_time = get_cmdb_token(secretKey, clientId, apiName)
        cmdb_url = '%s?taskid=%s' % (cmdb_url, task_id)
        cmdb_token = token
        cmdb_client_id = client_id
        cmdb_api_name = api_name
        cmdb_report_time = report_time
        main(cmdb_url, cmdb_token, cmdb_client_id, cmdb_api_name, cmdb_report_time)
        exit(0)
    except Exception as e:
        print("cmdb report script run error, {} \n {}".format(e.args, traceback.format_exc()))
        exit(-1)
    finally:
        delete_lock()