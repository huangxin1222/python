#!/usr/bin/env python
# coding:utf-8
"""A wrapper script with srvadmin and other tools for hardware monitor.
Supported metrics:
    cpu memory raidcard pdisk vdisk raidcard_bat
    bios cmos_bat fan power board_temp cpu_temp
    network_speed pcie
"""

import signal
import threading
import subprocess
import json
import time
import os
import sys
import commands
import socket
import urllib2
import re
import datetime
from pprint import pprint
from optparse import OptionParser
from subprocess import Popen, PIPE
from collections import defaultdict

info_list = []
heal = 1
BadBlocks = 0
Blocksnum = 0
LeftTime = 100
NETWORK_SPEED = 1
current_date = time.strftime('%Y-%m-%d')
filename = "/data/script/system/logs/script.%s.log" % current_date
error_occured = False
start_time = time.time()
timeout = 30

# 判断是为dell服务器
while True:
    machine = subprocess.check_output("dmidecode -s system-manufacturer", shell=True)
    dell = machine.split()[0]
    if dell != "Dell":
        time.sleep(31536000)
    else:
        break

#软件包判断
DEVNULL = open(os.devnull, 'w')
if os.system("systemd-detect-virt > /dev/null") == 0:
    tools = ["nvme", "shannon-utils"]
    for tool in tools:
        tool_path = subprocess.check_output(["which", tool])
        if tool_path.strip() == "":
            subprocess.call(["yum", "install", "-y", tool])
            print("安装了 {}".format(tool))
        else:
            break


file = '/usr/local/sbin/mip'
#安装mip软件
if not os.path.exists(file):
    mip_check = "rpm -q mip"
    if subprocess.call(mip_check, shell=True) != 0:
        strDown = "yum install mip -y;chmod a+x /usr/local/sbin/mip"
        subprocess.call(strDown, shell=True)
return_code, host = commands.getstatusoutput('/usr/local/sbin/mip')


#软件包判断
if subprocess.call('rpm -q net-tools > /dev/null', shell=True) != 0:
    os.system('yum install -y net-tools')
elif subprocess.call('rpm -q ethtool > /dev/null', shell=True) != 0:
    os.system('yum install -y ethtool')


def check_install_package():
    result = subprocess.call('rpm -q perccli > /dev/null', shell=True)
    if result == 0:
        pass
    else:
        subprocess.call('yum install -y perccli', shell=True)
check_install_package()


messages = []
verbs = []


def addverb(metric, model, index, status, info):
    # add metric info
    m = {}
    m['metric'] = metric
    m['model'] = model
    m['index'] = index
    m['status'] = status
    m['info'] = info
    verbs.append(m)


def addmsg(metric, value):
    # add endpoint to metric
    m = {}
    m['metric'] = 'hw.%s' % metric
    m['endpoint'] = host
    m['tags'] = ''
    m['value'] = value
    m['timestamp'] = int(time.time())
    m['step'] = int(step)
    m['counterType'] = 'GAUGE'
    messages.append(m)


def map_value(state):
    # Define levels
    statemap = {0: ['crit', 'critical'],
                1: ['warn', 'warning', 'non-critical'],
                2: ['ok', 'ready']
                }
    for i in statemap:
        if state.lower() in statemap[i]:
            return i


def execute(cmd):
    # Execute the command
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    return p.communicate()


def get_local_ip():
    try:
        output = subprocess.check_output(['/usr/local/sbin/mip']).encode('utf-8').strip()
        local_ip = output.split('\n')[0]
    except Exception as e:
        print("Error: %s" % (str(e)))
        local_ip = '127.0.0.1'
    return local_ip


def get_timestamp():
    return int(time.time())

IP = get_local_ip()
ts = get_timestamp()


#网速
def speed_check(path):
    if os.path.exists('{}/systemd-detect-virt'.format(path)):
        result = os.popen('{}/systemd-detect-virt'.format(path)).read().strip()
        if result == "none":
            cmd1 = '{}/mii-tool $NETWORK 2>/dev/null | grep "link ok"'.format(path)
            cmd2 = '{}/ethtool $NETWORK 2>/dev/null | grep "Link detected" | grep -i "yes"'.format(path)
            if os.popen(cmd1).read().strip() or os.popen(cmd2).read().strip():
                system_speed = os.popen('{}/ethtool $NETWORK | grep "Speed" | awk "{{print $2}}" | sed "s/[^0-9]//g"'.format(path)).read().strip()
                if int(system_speed) < 1000:
                    NETWORK_SPEED = 0
                else:
                    NETWORK_SPEED = 1
        else:
            NETWORK_SPEED = 1
    else:
        NETWORK_SPEED = 1

    return NETWORK_SPEED


#获取pcie
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)
    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None


def check_pcie_nvme():
    heal = BadBlocks = Blocksnum = LeftTime = 0
    if os.path.exists('/usr/sbin/nvme'):
        try:
            nvme_list_output = subprocess.check_output(['nvme', 'list'], stderr=subprocess.PIPE).decode('utf-8')
            pcie_list = [line.split()[0] for line in nvme_list_output.splitlines()[2:]]
            pcie_list = [str(pcie_name) for pcie_name in pcie_list]
            if pcie_list:
                for pcie_name in pcie_list:
                    pcie_flag = pcie_name.split('/')[-1]
                    try:
                        smart_output = subprocess.check_output(['nvme', 'smart-log', pcie_name]).decode('utf-8')
                        temp_heal_match = re.search(r'available spare:\s+(\d+)', smart_output)
                        temp_critical_warning_match = re.search(r'critical_warning:\s+(\d+)', smart_output)
                        temp_BadBlocks_match = re.search(r'bad_blocks:\s+(\d+)', smart_output)
                        percentage_used_match = re.search(r'percentage_used\s+:\s+(\d+%?)', smart_output)
                        if temp_heal_match:
                            temp_heal = temp_heal_match.group(1)
                            temp_critical_warning = temp_critical_warning_match.group(1) if temp_critical_warning_match else '0'
                            heal = 0 if int(temp_critical_warning) > 0 else int(temp_heal)
                        else:
                            temp_heal = '0'
                            heal = 0
                        if temp_BadBlocks_match:
                            temp_BadBlocks = temp_BadBlocks_match.group(1)
                            BadBlocks = float(temp_BadBlocks) if float(temp_BadBlocks) > BadBlocks else BadBlocks
                        log_file_path = "/data/falcon-agent/falcon-agent_1988/logs/{}_block.log".format(pcie_flag)
                        if os.path.exists(log_file_path):
                            with open(log_file_path, 'r') as f:
                                block_log_content = f.read()
                                blocks_list = re.findall(r'\d+\.\d+', block_log_content)
                                oldBlocksnum = float(blocks_list[0]) if blocks_list else 0
                        else:
                            oldBlocksnum = 0
                        if temp_BadBlocks_match and float(temp_BadBlocks) >= oldBlocksnum:
                            temp_Blocksnum = float(temp_BadBlocks) - oldBlocksnum
                            Blocksnum = temp_Blocksnum if temp_Blocksnum > Blocksnum else Blocksnum
                        else:
                            Blocksnum = 0
                        with open(log_file_path, "w") as f:
                            f.write(str(BadBlocks))
                        if percentage_used_match:
                            percentage_used = percentage_used_match.group(1)
                            percentage_used = int(percentage_used.rstrip('%'))
                            LeftTime = 100 - percentage_used
                            LeftTime = max(LeftTime, 1)
                        else:
                            print("No match found for percentage_used")
                        allMetric={
                                "pcie-BadBlocks":BadBlocks,
                                "pcie-BadBlocksnum":Blocksnum,
                                "pcie-Healthy":100 if heal > 0 else 1,
                                "pcie-LeftTime":LeftTime}
                        for m in allMetric:
                            pushallmetric(m,allMetric[m])
                    except subprocess.CalledProcessError as e:
                        print("运行命令时出错:", e)
        except subprocess.CalledProcessError:
            print("无法执行 'nvme list'")
    else:
        print("未找到 PCIe 设备")


def check_pcie_shannon():
    global heal, BadBlocks, Blocksnum, LeftTime
    if os.path.exists('/usr/bin/shannon-status') and subprocess.Popen(['/usr/bin/shannon-status', '-l'], stdout=subprocess.PIPE).communicate()[0]:
        shannon_list = subprocess.Popen(['/usr/bin/shannon-status', '--list'], stdout=subprocess.PIPE).communicate()[0]
        shannon_disk_num = len(shannon_list.splitlines())
        if shannon_disk_num > 0:
            heal = 0
            for i in range(1, shannon_disk_num + 1):
                ascii_value = i + 96
                letter = chr(ascii_value)
                shannon_disk_block_name = "df" + letter
                shannon_disk_name = "/dev/sct" + letter
                temp_heal = subprocess.Popen(['/usr/bin/shannon-status', shannon_disk_name], stdout=subprocess.PIPE).communicate()[0]
                heal_lines = [x for x in temp_heal.splitlines() if 'Media Status' in x and 'Healthy' in x.lower()]
                if heal_lines:
                    heal = len(heal_lines)
                else:
                    pass
                temp_BadBlocks = subprocess.Popen(['/usr/bin/shannon-status', shannon_disk_name], stdout=subprocess.PIPE).communicate()[0]
                BadBlocks = float(temp_BadBlocks.split('Dynamic Bad Blocks')[1].split(':')[1].strip().split()[0])
                log_path = "/data/falcon-agent/falcon-agent_1988/logs/{}_block.log".format(shannon_disk_block_name)
                if os.path.isfile(log_path):
                    oldBlocksnum = float(open(log_path).read().strip() or 0)
                else:
                    oldBlocksnum = 0
                if BadBlocks >= oldBlocksnum:
                    temp_Blocksnum = BadBlocks - oldBlocksnum
                    Blocksnum = max(temp_Blocksnum, Blocksnum)
                else:
                    Blocksnum = 0
                with open(log_path, 'w') as log_file:
                    log_file.write(str(BadBlocks))
                temp_LeftTime = subprocess.Popen(['/usr/bin/shannon-status', shannon_disk_name], stdout=subprocess.PIPE).communicate()[0]
                LeftTime = int(float(temp_LeftTime.split('Estimated Life Left')[1].split(':')[1].strip().split('%')[0]))
                allMetric={
                        "pcie-BadBlocks":BadBlocks,
                        "pcie-BadBlocksnum":Blocksnum,
                        "pcie-Healthy":100 if heal > 0 else 1,
                        "pcie-LeftTime":LeftTime}
                for m in allMetric:
                    pushallmetric(m,allMetric[m])


def pushallmetric(m, v,):
    info_list = []
    info_list.append({"metric": m, "endpoint": IP, "timestamp": ts, "step": 1800, "value": v, "counterType": "GAUGE", "tags": ""})
    json_output = json.dumps(info_list)
    try:
        url = "http://127.0.0.1:1988/v1/push"
        headers = {'Content-Type': 'application/json'}
        req = urllib2.Request(url, json_output, headers)
        response = urllib2.urlopen(req)
    except urllib2.HTTPError as e:
        print("HTTP Error: {} - {}".format(e.code, e.reason))
    except urllib2.URLError as e:
        print("URL Error: {}".format(e.reason))
    except Exception as e:
        print("An error occurred: {}".format(str(e)))


def check_cpu():
    # 获取cpu的状态信息是否 OK
    # cpu | x3430 | cpu1 | ok | present
    cmd = 'timeout 10s omreport chassis processors -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr is not None:
        return
    cpus = [cpu for cpu in stdout.splitlines() if 'CPU' in cpu]
    value = 2
    if len(cpus) == 1:
        # 单个CPU
        line = cpus[0]
        i = line.split(';')
        Status = i[1].strip().lower()
        Connector_Name = i[2].strip().lower()
        State = i[6].strip().lower()
        # 检查 Processor_Brand 是否包含足够的元素
        if len(i) > 3:
            Processor_Brand = i[3].strip().lower()
            brand_parts = Processor_Brand.split()
            if len(brand_parts) > 3:
                model = brand_parts[3]
                v = map_value(Status)
                if v < value:
                    value = v
                addverb('cpu', model, Connector_Name, Status, State)
            else:
                print("Processor_Brand does not contain enough parts.")
    elif len(cpus) > 1:
        # 多个CPU
        for line in cpus:
            i = line.split(';')
            Status = i[1].strip().lower()
            Connector_Name = i[2].strip().lower()
            State = i[6].strip().lower()
            # 检查 Processor_Brand 是否包含足够的元素
            if len(i) > 3:
                Processor_Brand = i[3].strip().lower()
                brand_parts = Processor_Brand.split()
                if len(brand_parts) > 3:
                    model = brand_parts[3]
                    v = map_value(Status)
                    if v < value:
                        value = v
                    addverb('cpu', model, Connector_Name, Status, State)
                else:
                    print("Processor_Brand does not contain enough parts.")
    addmsg('cpu', value)


def check_memory():
    # 检内存状态是否OK
    # memory | ddr3 - synchronous unregistered (unbuffered) | dimm_a1 | ok | 4096  MB
    cmd = 'timeout 10s omreport chassis memory -fmt ssv'
    stdout, stderr = execute(cmd)
    #if stderr != None:
    if stderr is not None or not any([';A' in stdout, ';B' in stdout, 'DIMM' in stdout]):
        return
    mems = [mem for mem in stdout.splitlines(
    ) if ';A' in mem or ';B' in mem or 'DIMM' in mem]
    value = 2
    memory_data_found = False
    for line in mems:
        i = line.split(';')
        if len(i) < 5:
            continue
        # TODO make sure index here is uniq
        # Index = i[0].strip()
        Status = i[1].strip().lower()
        Connector_Name = i[2].strip().lower()
        Type = i[3].strip().lower()
        Size = i[4].strip()
        if not all([Status, Connector_Name, Type, Size]):
            continue
        if Status == 'unknown':
            continue
        # index = Connector_Name.lstrip(';A') or Connector_Name.lstrip(
            # ';B') or Connector_Name.lstrip('dimm_')
        v = map_value(Status)
        if v < value:
            value = v
        memory_data_found = True
        addverb('memory', Type, Connector_Name, Status, Size)
    addmsg('memory', value)


# disk raidcard
def get_controller_info():
    command = '/opt/MegaRAID/perccli/perccli64 show all J'
    try:
        output = subprocess.check_output(command, shell=True)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return None


#raidcard
def check_raidcard():
    command_output = get_controller_info()
    json_output = json.loads(command_output)
    if 'Controllers' in json_output:
        for controller in json_output['Controllers']:
            if 'Response Data' in controller and 'System Overview' in controller['Response Data']:
                system_overview = controller['Response Data']['System Overview']
                if len(system_overview) > 0:
                    health_status = system_overview[0].get('Hlth', None)
                    if health_status in ['Opt', 'NdAtn']:
                        value = 2
                    elif health_status in ['Dgd', 'Fld']:
                        value = 0
                    else:
                        value = 0
                    addmsg('raidcard', value)
                    print("this is raidcard", value)


# pdisk
def check_pdisk():
    command = "/opt/MegaRAID/perccli/perccli64 /c0 show J"
    try:
        output = subprocess.check_output(command, shell=True)
        data = json.loads(output)
        onln_pdisks = 0
        total_pdisks = 0
        not_onln_pdisks = 0
        controllers = data.get("Controllers", [])
        if controllers:
            for controller in controllers:
                response_data = controller.get("Response Data", {})
                pd_list = response_data.get("PD LIST", [])
                total_pdisks += len(pd_list)
                for pdisk in pd_list:
                    state = pdisk.get("State", "")
                    if state == "Failed" or state == "Offline":
                        not_onln_pdisks += 1
                    else:
                        onln_pdisks += 1
                    if state in ["UGood", "UBad", "DHS", "JBOD"]:
                        current_date = time.strftime('%Y-%m-%d')
                        with open(filename, "a") as file:
                            file.write("State of {} on pdisk\n".format(state))
        if not_onln_pdisks == 0:
            value = 2
        elif not_onln_pdisks == 1:
            value = 0
        else:
            value = 2
        addmsg('pdisk', value)
        print("this is pdisk",value)
        return value
    except subprocess.CalledProcessError as e:
        return -1


# vdisk
def check_vdisk():
    command = "/opt/MegaRAID/perccli/perccli64 /c0 show J"
    try:
        output = subprocess.check_output(command, shell=True)
        data = json.loads(output)
        not_onln_vdisks = 0
        total_vdisks = 0
        onln_vdisks = 0
        failed_or_offline_pdisks = False
        controllers = data.get("Controllers", [])
        if controllers:
            for controller in controllers:
                response_data = controller.get("Response Data", {})
                vd_list = response_data.get("VD LIST", [])
                total_vdisks += len(vd_list)
                for vdisk in vd_list:
                    if vdisk.get("State") == "Dgrd":
                        if failed_or_offline_pdisks:
                            value = 0
                            addmsg('vdisk', value)
                            return value
                        not_onln_vdisks += 1
                    else:
                        onln_vdisks += 1
            if not_onln_vdisks > 0 and failed_or_offline_pdisks:
                value = 0
            else:
                value = 2
            addmsg('vdisk', value)
            print("this is vdisk", value)
            return value
    except subprocess.CalledProcessError as e:
        return -1  # 返回-1


# raidcard battery
def check_raidcard_bat():
    # 检查raidcard 的电池是否OK
    # raidcard_bat | Battery | 0 | ok | Not Applicable
    cmd = 'timeout 10s omreport storage battery -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    batteries = [bat for bat in stdout.splitlines() if 'Battery' in bat]
    if not batteries:
        return
    value = 2
    for line in batteries:
        i = line.split(';')
        ID = i[0].strip()
        Status = i[1].strip()
        Name = i[2].strip()
        Learn_State = i[6].strip()
        v = map_value(Status)
        if v < value:
            value = v
        addverb('raidcard_bat', Name, ID, Status, Learn_State)
    addmsg('raidcard_bat', value)


def check_bios():
    # Processor C State Control 是否开启
    # bios | bios_setting | Processor C State Control | ok |Enabled
    cmd = 'timeout 10s omreport chassis biossetup -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    bsets = [b for b in stdout.splitlines() if 'C State' in b or 'C1-E' in b or
             'C1E' in b]
    if not bsets:
        return
    value = 2
    for line in bsets:
        i = line.split(';')
        ATTRIBUTE = i[0].strip().lower()
        VALUE = i[1].strip()
        if VALUE == 'Enabled':
            Status = 'warn'
        elif VALUE == 'Disabled':
            Status = 'ok'
        else:
            continue
        if VALUE == "Disabled":
            index_list=[]
            index_list.append(ATTRIBUTE)
            index_list.append(check_bios_Disabled())
            ATTRIBUTE = index_list
        v = map_value(Status)
        if v < value:
            value = v
        addverb('bios', "bios_setting", ATTRIBUTE, Status, VALUE)
    addmsg('bios', value)


def check_bios_Disabled():
    # 多版本bios
    cmd = "timeout 10s omreport chassis biossetup display=shortnames | grep 'SysProfile'"
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    bsets = [b for b in stdout.splitlines() if 'PerfOptimized' in b]
    if not bsets:
        return
    #value = 2
    v_index=bsets[0].split(":")[1].strip()
    return v_index


def check_cmos_bat():
    # cmos电池是否 OK
    # cmos_bat | System Board CMOS Battery| 0 | ok | Good
    cmd = 'timeout 10s omreport chassis batteries -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    bats = [battery for battery in stdout.splitlines() if 'CMOS' in battery]
    if not bats:
        return
    value = 2
    for line in bats:
        i = line.split(';')
        Index = i[0].strip()
        Status = i[1].strip()
        Probe_Name = i[2].strip()
        Reading = i[3].strip()
        v = map_value(Status)
        if v < value:
            value = v
        addverb('cmos_bat', Probe_Name, Index, Status, Reading)
    addmsg('cmos_bat', value)


def check_fan():
    # 检查风扇是否故障
    # fan | System Board FAN MOD 1A RPM | 0 | ok | 4920 RPM
    cmd = 'timeout 10s omreport chassis fans -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    fans = [fan for fan in stdout.splitlines() if 'RPM' in fan]
    if not fans:
        return
    value = 2
    for line in fans:
        i = line.split(';')
        if len(i) < 4:
            continue
        Index = i[0].strip()
        Status = i[1].strip()
        Probe_Name = i[2].strip()
        Reading = i[3].strip()
        v = map_value(Status)
        if v < value:
            value = v
        addverb('fan', Probe_Name, Index, Status, Reading)
    addmsg('fan', value)


def check_power():
    # 检查机器电源能量消耗情况
    # System Peak Power;Tue Jan 28 14:41:52 2014;Thu Jun  4 06:31:40 2020;396 W
    # System Peak Amperage;Tue Jan 28 14:41:52 2014;Thu Jun  4 06:31:40 2020;3.7 A
    cmd = 'timeout 10s omreport chassis pwrmonitoring -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    powers = [pwr for pwr in stdout.splitlines() if 'System Board' in pwr]
    if not powers:
        return
    value = 2
    for line in powers:
        i = line.split(';')
        Index = i[0].strip()
        Status = i[1].strip()
        Probe_Name = i[2].strip()
        Reading = i[3].strip()
        w = Reading.split()[0]
        if w > value:
            value = w
        addverb('power', Probe_Name, Index, Status, Reading)
    addmsg('power', value)


# power_status
def check_power_status():
    # 检查电源的运行状态是否OK
    # power_status | PS1 Status | 0 | ok | Presence Detected, AC Lostd
    cmd = 'timeout 10s omreport chassis pwrsupplies -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    powers_status = [pwr for pwr in stdout.splitlines()
                     if 'Presence Detected' in pwr]
    if not powers_status:
        return
    value = 2
    for line in powers_status:
        i = line.split(';')
        Index = i[0].strip()
        Status = i[1].strip()
        Probe_Name = i[2].strip()
        # Reading = i[5].strip()
        # Firmware_Version = i[6].strip()
        Online_Status = i[7].strip()
        v = map_value(Status)
        if v < value:
            value = v
        addverb('power_status', Probe_Name, Index, Status, Online_Status)
    addmsg('power_status', value)


def check_board_temp():
    # 检查System Board Inlet|Exhaust的温度,即主板
    # board_temp | System Board Inlet Temp | 0 | ok | 23
    cmd = 'timeout 10s omreport chassis temps -fmt ssv'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    temp = [t for t in stdout.splitlines() if 'Board' in t]
    if not temp:
        return
    value = 2
    for line in temp:
        i = line.split(';')
        Index = i[0].strip()
        Status = i[1].strip()
        Probe_Name = i[2].strip()
        Reading = i[3].strip().split()[0]
        v = float(Reading)
        if v > value:
            value = v
        addverb('board_temp', Probe_Name, Index, Status, Reading)
    addmsg('board_temp', value)


def check_cpu_temp():
    # 检查CPU温度
    cmd = 'timeout 10s sensors'
    stdout, stderr = execute(cmd)
    if stderr != None:
        return
    lines = stdout.splitlines()
    temps = []
    id = False
    temp = {}
    for line in lines:
        if line.startswith('coretemp'):
            if line != id:
                id = line
                temp = {}
                value = 0
                temp['id'] = id
        elif line.startswith('Core'):
            lastcore = True
            key = line.split(':')[0]
            vv = line.split(':')[1].split()[0]
            v = vv.split('\xc2\xb0C')[0].split('+')[1]
            if float(v) > value:
                value = float(v)
                temp['core'] = key
                temp['reading'] = value
        elif line == '' and lastcore:
            if len(temp) != 0:
                temps.append(temp)
        else:
            lastcore = False
    value = 2
    for temp in temps:
        Index = '%d' % temps.index(temp)
        Probe_Name = temp['id']
        Reading = temp['reading']
        Maximum_Warning_Threshold = 80
        Maximum_Failure_Threshold = 90
        if Reading >= Maximum_Failure_Threshold:
            Status = 'crit'
        elif Reading >= Maximum_Warning_Threshold:
            Status = 'warn'
        else:
            Status = 'ok'
        if Reading > value:
            value = Reading
        addverb('cpu_temp', Probe_Name, Index, Status, Reading)
    addmsg('cpu_temp', value)


def check_pcie_functions():
    result_nvme = check_pcie_nvme()
    result_shannon = check_pcie_shannon()
    return result_nvme, result_shannon


def check(target=False):
    # 定义一个字典，将target参数映射到对应的函数
    check_functions = {
        'cpu': check_cpu,
        'cpu_temp':check_cpu_temp,
        'memory': check_memory,
        'raidcard': check_raidcard,
#        'pdisk': lambda: check_pdisk(check_raidcard()),
        'pdisk': lambda: check_pdisk(),
#        'vdisk': lambda: check_vdisk(check_raidcard()),
        'vdisk': lambda: check_vdisk(),
        'raidcard_bat': check_raidcard_bat,
        'cmos_bat': check_cmos_bat,
        'bios': check_bios,
        'fan': check_fan,
        'power': check_power,
        'power_status': check_power_status,
        'board_temp': check_board_temp,
        'pcie': check_pcie_functions
    }

    if not target:
        # 如果target参数为False，执行所有的检查操作
        for function in check_functions.values():
            function()
    elif target in check_functions:
        # 如果target参数在字典中，执行对应的检查操作
        check_functions[target]()
    else:
        print("Unknown target: {target}")
    return messages


def push(message):
    try:
        urllib2.urlopen(
            url='http://127.0.0.1:1988/v1/push',
            data=json.dumps(message)
        )
    except:
        pass


current_time = time.time()
time_elapsed = current_time % (30 * 60)
last_execution_time = current_time - time_elapsed
IP = get_local_ip()


while True:
    ts = get_timestamp()
    if os.popen('/usr/bin/systemd-detect-virt > /dev/null 2>&1').read().strip() == "none":
            networks = os.popen('ls /etc/sysconfig/network-scripts/ifcfg-* | awk -F- "{{print $NF}}" | grep ^e').read().strip().split('\n')
            for network in networks:
                if os.popen('cat /etc/redhat-release | grep "6."').read().strip():
                    speed_check('/sbin')
                elif os.popen('cat /etc/redhat-release | grep "7."').read().strip():
                    speed_check('/usr/sbin')
            DATA = [{"metric": "network_speed", "endpoint": IP, "timestamp": ts, "step": 1800, "value": NETWORK_SPEED, "counterType": "GAUGE", "tags": ""}]
    else:
         DATA = [{"metric": "network_speed", "endpoint": IP, "timestamp": ts, "step": 1800, "value": "1", "counterType": "GAUGE", "tags": ""}]

    # 列出metrics支持的option
    metrics = ['cpu', 'memory', 'raidcard', 'pdisk', 'vdisk', 'raidcard_bat',
               'bios', 'cmos_bat', 'fan', 'power', 'power_status', 'board_temp', 'cpu_temp','pcie']
    parser = OptionParser()
    parser.add_option("-p", "--push", action="store_true",
                      dest="push", help="push result to agent")
    parser.add_option("-d", "--debug", action="store_true",
                      dest="debug", help="output debug info")
    parser.add_option("-m", "--metric", action="store",
                      dest="metric", help="check special metric")
    parser.add_option("-s", "--step", action="store",
                      dest="step", help="check special metric")
    (options, args) = parser.parse_args()

    #判断上报
    if not options.step:
        step = 1800
    else:
        step = int(options.step)
    metric = None
    if options.metric:
        metric = options.metric
        if metric not in metrics:
            print(__doc__)
            parser.print_help()
            break
    messages = check(target=metric)
    new_data = DATA[0]
    messages.append(new_data)
    if options.push:
        push(messages)
    elif not options.push and len(messages) > 0:
        metrics_to_check = ["hw.memory","hw.pdisk", "hw.vdisk", "hw.raidcard", "hw.fan"]
        msg_list=[]
        with open(filename, 'a') as f:
            for msg in messages:
               f.write(str(msg) + '\n')
               if msg["metric"] in metrics_to_check:
                   msg_list.append(msg["metric"])
            #msg_list.append(msg["metric"])
        error_metrics=[]
        for m in metrics_to_check:
            if m not in msg_list:
                error_metrics.append(m)
        with open(filename, 'a') as f:
            if error_metrics:
                data_error = "hardware no data>> {}  ".format(str(error_metrics))
                f.write(data_error + "\n")
        push(messages)
    elif options.push or len(messages) > 0:
        if options.debug:
            print(json.dumps({'status': '上报成功', 'data': messages}, indent=2))
        else:
            print(json.dumps({'status': '上报成功', 'reason': ''}, indent=2))
    else:
        if options.debug:
            print(json.dumps({'status': '上报失败', 'data': messages}, indent=2))
        else:
            print(json.dumps({'status': '上报失败', 'reason': verbs}, indent=2))

    current_time = time.time()
    time_elapsed = current_time - last_execution_time
    remainder = (time_elapsed / 60) % 30
    epsilon = 0.01
    #if remainder == 0:
    if abs(remainder) < epsilon:
        print("Executing code at:", current_time)
        last_execution_time = current_time
    else:
        delay = (30 - remainder) * 60
        print("Waiting for", delay / 60, "minutes until the next multiple of 30")
        time.sleep(delay)

    messages=[]
