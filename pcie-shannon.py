# coding:utf-8
import subprocess
import json
import os

def check_pcie_shannon():
    pcie_cards = []
    lspci_output = subprocess.Popen(['lspci'], stdout=subprocess.PIPE).communicate()[0]
    lspci_lines = lspci_output.splitlines()
    brand = ""
    for idx, line in enumerate(lspci_lines):
        if 'Intel Corporation' in line:
            # Look for the subsequent line that might contain the device name
            if idx + 1 < len(lspci_lines):
                next_line = lspci_lines[idx + 1]
                if any(keyword in next_line for keyword in ['Ethernet controller', 'SATA controller', 'RAID bus controller']):
                    brand = 'Intel Corporation'  # Set brand to Intel Corporation
                    break  # Exit loop after finding the brand
    if not brand:
        print("未能获取品牌信息")
        return {"pcie_cards": pcie_cards}
    if subprocess.call(['lspci'], stdout=subprocess.PIPE) != 0:
        print("该服务器上没有PCIe设备")
        return pcie_cards
    if os.path.exists('/usr/bin/shannon-status'):
        shannon_list = subprocess.Popen(['/usr/bin/shannon-status', '--list'], stdout=subprocess.PIPE).communicate()[0]
        shannon_disk_num = len(shannon_list.splitlines())
        if shannon_disk_num > 0:
            for i in range(1, shannon_disk_num + 1):
                ascii_value = i + 96
                letter = chr(ascii_value)
                shannon_disk_name = "/dev/sct" + letter
                temp_heal = subprocess.Popen(['/usr/bin/shannon-status', shannon_disk_name], stdout=subprocess.PIPE).communicate()[0]
                heal_lines = [x for x in temp_heal.splitlines() if 'Media Status' in x and 'Healthy' in x.lower()]
                heal = "ok" if not heal_lines else 0
                temp_LeftTime = subprocess.Popen(['/usr/bin/shannon-status', shannon_disk_name], stdout=subprocess.PIPE).communicate()[0]
                LeftTime = int(float(temp_LeftTime.split('Estimated Life Left')[1].split(':')[1].strip().split('%')[0]))
                temp_capacity = subprocess.Popen(['/usr/bin/shannon-status', shannon_disk_name], stdout=subprocess.PIPE).communicate()[0]
                disk_capacity_lines = [x for x in temp_capacity.splitlines() if 'Disk Capacity' in x]
                size = ""
                if disk_capacity_lines:
                    size = disk_capacity_lines[0].split(':')[1].strip()
                    size = str(int(float(size.split()[0]))) if size else ""
                disk_status = "Online" if heal == "ok" else "Unonline"
                pcie_card = {
                    "disk_desc": brand,
                    "disk_status": disk_status,
                    "pcie_BadBlocks": "0",
                    "pcie_Healthy": heal,
                    "pcie_LeftTime": "{}".format(LeftTime),
                    "size": size
                }
                pcie_cards.append(pcie_card)

#    return pcie_cards
    return pcie_cards if pcie_cards else {}

output_data = check_pcie_shannon()

server_data = {"pcie_cards": output_data}
print(json.dumps(server_data))