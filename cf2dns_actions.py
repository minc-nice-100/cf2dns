#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, requests, time, base64, shutil, random, traceback
import ipaddress

# ==================== 华为云DNS API模块 ====================
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2 import *
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion

class HuaWeiApi():
    def __init__(self, ACCESSID, SECRETKEY, REGION = 'cn-east-3'):
        self.AK = ACCESSID
        self.SK = SECRETKEY
        self.region = REGION
        self.client = DnsClient.new_builder().with_credentials(BasicCredentials(self.AK, self.SK)).with_region(DnsRegion.value_of(self.region)).build()
        self.zone_id = self.get_zones()

    def del_record(self, domain, record):
        request = DeleteRecordSetsRequest()
        request.zone_id = self.zone_id[domain + '.']
        request.recordset_id = record
        response = self.client.delete_record_sets(request)
        result = json.loads(str(response))
        print(result)
        return result

    def get_record(self, domain, length, sub_domain, record_type):
        request = ListRecordSetsWithLineRequest()
        request.limit = length
        request.type = record_type
        if sub_domain == '@':
            request.name = domain + "."
        else:
            request.name = sub_domain + '.' + domain + "."
        response = self.client.list_record_sets_with_line(request)
        data = json.loads(str(response))
        result = {}
        records_temp = []
        for record in data['recordsets']:
            if (sub_domain == '@' and domain + "." == record['name']) or (sub_domain + '.' + domain + "." == record['name']):
                record['line'] = self.line_format(record['line'])
                # 获取记录的values列表
                if 'records' in record and record['records']:
                    # 对于多条记录，我们只取第一条用于兼容性
                    record['value'] = record['records'][0] if record['records'] else ''
                records_temp.append(record)
        result['data'] = {'records': records_temp}
        return result

    def create_record(self, domain, sub_domain, value, record_type, line, ttl):
        request = CreateRecordSetWithLineRequest()
        request.zone_id = self.zone_id[domain + '.']
        if sub_domain == '@':
            name = domain + "."
        else:
            name = sub_domain + '.' + domain + "."
        
        # value可以是单个IP或IP列表
        records = value if isinstance(value, list) else [value]
        
        request.body = CreateRecordSetWithLineReq(
            type = record_type,
            name = name,
            ttl = ttl,
            weight = 1,
            records = records,
            line = self.line_format(line)
        )
        response = self.client.create_record_set_with_line(request)
        result = json.loads(str(response))
        return result
        
    def change_record(self, domain, record_id, sub_domain, value, record_type, line, ttl):
        """
        更新记录集，支持单个IP或IP列表
        :param value: 可以是单个IP字符串，也可以是IP列表
        """
        request = UpdateRecordSetRequest()
        request.zone_id = self.zone_id[domain + '.']
        request.recordset_id = record_id
        if sub_domain == '@':
            name = domain + "."
        else:
            name = sub_domain + '.' + domain + "."
        
        # value可以是单个IP或IP列表
        records = value if isinstance(value, list) else [value]
        
        request.body = UpdateRecordSetReq(
            name = name,
            type = record_type,
            ttl = ttl,
            records = records
        )
        response = self.client.update_record_set(request)
        result = json.loads(str(response))
        return result

    def get_zones(self):
        request = ListPublicZonesRequest()
        response = self.client.list_public_zones(request)
        result = json.loads(str(response))
        zone_id = {}
        for zone in result['zones']:
            zone_id[zone['name']] = zone['id'] 
        return zone_id

    def line_format(self, line):
        lines = {
            # 中文转华为云线路代码
            '默认' : 'default_view',
            '电信' : 'Dianxin',
            '联通' : 'Liantong',
            '移动' : 'Yidong',
            '教育网' : 'Education',
            '铁通' : 'Tietong',
            '鹏博士' : 'Drpeng',
            '境外' : 'Abroad',
            
            # 华为云线路代码转中文（用于get_record返回）
            'default_view' : '默认',
            'Dianxin' : '电信',
            'Liantong' : '联通',
            'Yidong' : '移动',
            'Education' : '教育网',
            'Tietong' : '铁通',
            'Drpeng' : '鹏博士',
            'Abroad' : '境外',
        }
        return lines.get(line, line)  # 如果找不到映射，返回原值

# ==================== 主程序部分 ====================

# 从环境变量获取配置
config = json.loads(os.environ["CONFIG"])
# CM:移动 CU:联通 CT:电信 ED:教育网 TT:铁通 PBS:鹏博士 DEF:默认
DOMAINS = json.loads(os.environ["DOMAINS"])
# 获取服务商信息
provider_data = json.loads(os.environ["PROVIDER"])

# ==================== 从环境变量获取CIDR配置 ====================
def get_cidrs_from_env(env_var_name):
    """
    从环境变量获取CIDR列表
    环境变量中的CIDR可以是每行一个，或者用逗号分隔
    """
    cidr_str = os.environ.get(env_var_name, "")
    if not cidr_str:
        return []
    
    # 尝试按行分割，然后按逗号分割，过滤空值
    cidrs = []
    for line in cidr_str.split('\n'):
        for cidr in line.split(','):
            cidr = cidr.strip()
            if cidr and not cidr.startswith('#'):  # 忽略空行和注释
                cidrs.append(cidr)
    
    return cidrs

# 从环境变量获取IPv4 CIDR列表
IPV4_CIDRS = get_cidrs_from_env("IPV4_CIDRS")

# 从环境变量获取IPv6 CIDR列表
IPV6_CIDRS = get_cidrs_from_env("IPV6_CIDRS")

# 从环境变量获取每个运营商生成的IP数量（默认50）
try:
    IP_COUNT_PER_ISP = int(os.environ.get("IP_COUNT_PER_ISP", "50"))
except ValueError:
    IP_COUNT_PER_ISP = 50

# 打印CIDR配置信息
print("=" * 50)
print("CIDR配置信息:")
print(f"IPv4 CIDRs ({len(IPV4_CIDRS)} 个):")
for cidr in IPV4_CIDRS:
    print(f"  - {cidr}")
print(f"IPv6 CIDRs ({len(IPV6_CIDRS)} 个):")
for cidr in IPV6_CIDRS:
    print(f"  - {cidr}")
print(f"每个运营商IP数量: {IP_COUNT_PER_ISP}")
print("=" * 50)

# ==================== IP黑名单配置 ====================
# 支持CIDR格式，可以添加IPv4和IPv6网段
CUSTOM_BLACKLIST = get_cidrs_from_env("CUSTOM_BLACKLIST")

IP_BLACKLIST_CIDR = [
    "192.168.1.0/24",  # 屏蔽192.168.1.x整个网段
    "10.0.0.0/8",      # 屏蔽10.x.x.x整个A类私有地址
    "172.16.0.0/12",   # 屏蔽172.16.x.x - 172.31.x.x私有地址
    "127.0.0.0/8",     # 屏蔽本地回环地址
    "0.0.0.0/8",       # 屏蔽无效地址
    "100.64.0.0/10",   # 屏蔽运营商级NAT地址
    "169.254.0.0/16",  # 屏蔽链路本地地址
    "224.0.0.0/4",     # 屏蔽组播地址
    "240.0.0.0/4",     # 屏蔽保留地址
    "::1/128",         # 屏蔽IPv6回环地址
    "fc00::/7",        # 屏蔽唯一本地地址
    "fe80::/10",       # 屏蔽链路本地地址
    "ff00::/8",        # 屏蔽组播地址
]

# 添加自定义黑名单
if CUSTOM_BLACKLIST:
    IP_BLACKLIST_CIDR.extend(CUSTOM_BLACKLIST)
    print(f"已添加 {len(CUSTOM_BLACKLIST)} 个自定义黑名单网段")

# 编译IP黑名单网络对象
IP_BLACKLIST_NETWORKS = []

def compile_blacklist():
    """编译IP黑名单CIDR列表为ipaddress网络对象"""
    global IP_BLACKLIST_NETWORKS
    IP_BLACKLIST_NETWORKS = []

    for cidr in IP_BLACKLIST_CIDR:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            IP_BLACKLIST_NETWORKS.append(network)
            print(f"添加黑名单网段: {cidr} ({'IPv4' if network.version == 4 else 'IPv6'})")
        except ValueError as e:
            print(f"警告: CIDR格式错误 '{cidr}': {str(e)}")
        except Exception as e:
            print(f"警告: 解析CIDR '{cidr}' 时发生未知错误: {str(e)}")

    print(f"IP黑名单初始化完成，共加载 {len(IP_BLACKLIST_NETWORKS)} 个网段")

def is_ip_blacklisted(ip):
    """检查IP是否在黑名单中"""
    try:
        ip_addr = ipaddress.ip_address(ip)
        for network in IP_BLACKLIST_NETWORKS:
            if ip_addr in network:
                print(f"IP {ip} 匹配黑名单网段 {network}")
                return True
        return False
    except ValueError as e:
        print(f"警告: IP地址格式错误 '{ip}': {str(e)}")
        return False
    except Exception as e:
        print(f"警告: 检查IP黑名单时发生错误 '{ip}': {str(e)}")
        return False

def filter_blacklist_ips(ip_list):
    """过滤掉黑名单中的IP"""
    filtered_ips = []
    blocked_ips = []

    for ip_info in ip_list:
        if isinstance(ip_info, dict):
            ip = ip_info.get("ip", "")
        elif isinstance(ip_info, str):
            ip = ip_info
            ip_info = {"ip": ip}
        else:
            continue

        if ip and not is_ip_blacklisted(ip):
            filtered_ips.append(ip_info)
        elif ip:
            blocked_ips.append(ip)

    if blocked_ips:
        print(f"过滤掉 {len(blocked_ips)} 个黑名单IP: {blocked_ips[:5]}{'...' if len(blocked_ips) > 5 else ''}")

    return filtered_ips, blocked_ips

# 编译黑名单
compile_blacklist()

# ==================== 从CIDR生成随机IP的函数 ====================

def generate_random_ip_from_cidr(cidr):
    """
    从CIDR中随机生成一个可用的IP地址
    排除网络地址和广播地址
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        # 获取网络中的主机数量
        num_hosts = network.num_addresses
        
        if network.version == 4:
            # IPv4: 排除网络地址和广播地址
            if num_hosts <= 2:
                print(f"警告: CIDR {cidr} 主机位不足，无法分配可用IP")
                return None
            
            # 随机选择一个主机索引（排除第一个和最后一个）
            host_index = random.randint(1, num_hosts - 2)
            ip = network.network_address + host_index
        else:
            # IPv6: 通常没有广播地址的概念，但排除网络地址本身
            if num_hosts <= 1:
                print(f"警告: CIDR {cidr} 主机位不足，无法分配可用IP")
                return None
            
            # 随机选择一个主机索引（排除第一个）
            host_index = random.randint(1, num_hosts - 1)
            ip = network.network_address + host_index
        
        return str(ip)
    except Exception as e:
        print(f"从CIDR {cidr} 生成IP时出错: {str(e)}")
        return None

def generate_random_ips_from_cidrs(cidr_list, count, is_v6=False):
    """
    从CIDR列表中随机生成指定数量的IP
    返回IP信息列表（只包含IP地址）
    """
    if not cidr_list:
        print(f"警告: {'IPv6' if is_v6 else 'IPv4'} CIDR列表为空")
        return []
    
    ip_list = []
    attempts = 0
    max_attempts = count * 20  # 防止无限循环
    
    while len(ip_list) < count and attempts < max_attempts:
        attempts += 1
        
        # 随机选择一个CIDR
        cidr = random.choice(cidr_list)
        
        # 生成随机IP
        ip = generate_random_ip_from_cidr(cidr)
        
        if ip and not is_ip_blacklisted(ip):
            # 只存储IP地址，不添加任何假参数
            ip_info = {"ip": ip}
            
            # 检查是否重复
            if ip not in [existing["ip"] for existing in ip_list]:
                ip_list.append(ip_info)
    
    print(f"从 {len(cidr_list)} 个 {'IPv6' if is_v6 else 'IPv4'} CIDR中生成了 {len(ip_list)} 个IP")
    return ip_list

def get_random_ips():
    """
    从CIDR生成IP信息
    支持所有线路类型
    """
    # 存储生成的IP信息 - 扩展支持所有线路
    generated_ips = {
        "v4": {"CM": [], "CU": [], "CT": [], "ED": [], "TT": [], "PBS": [], "DEF": []},
        "v6": {"CM": [], "CU": [], "CT": [], "ED": [], "TT": [], "PBS": [], "DEF": []}
    }
    
    # 所有支持的线路
    all_isps = ["CM", "CU", "CT", "ED", "TT", "PBS", "DEF"]
    isp_count = len(all_isps)
    
    # 从IPv4 CIDR生成IP
    if IPV4_CIDRS:
        ipv4_ips = generate_random_ips_from_cidrs(IPV4_CIDRS, IP_COUNT_PER_ISP * isp_count, is_v6=False)
        # 平均分配给所有运营商
        for i, isp in enumerate(all_isps):
            start_idx = i * IP_COUNT_PER_ISP
            end_idx = start_idx + IP_COUNT_PER_ISP
            if start_idx < len(ipv4_ips):
                generated_ips["v4"][isp] = ipv4_ips[start_idx:end_idx]
    
    # 从IPv6 CIDR生成IP
    if IPV6_CIDRS:
        ipv6_ips = generate_random_ips_from_cidrs(IPV6_CIDRS, IP_COUNT_PER_ISP * isp_count, is_v6=True)
        # 平均分配给所有运营商
        for i, isp in enumerate(all_isps):
            start_idx = i * IP_COUNT_PER_ISP
            end_idx = start_idx + IP_COUNT_PER_ISP
            if start_idx < len(ipv6_ips):
                generated_ips["v6"][isp] = ipv6_ips[start_idx:end_idx]
    
    # 构建返回数据
    result = {
        "code": 200,
        "info": generated_ips[iptype]
    }
    
    return result

# ==================== DNS更新函数 ====================

def batch_update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl, affect_num):
    """批量更新华为云DNS记录"""
    try:
        existing_ips = [record["value"] for record in existing_records]
        
        # 直接使用新IP，随机选择
        if len(new_ips) > affect_num:
            # 随机选择 affect_num 个IP
            selected_ips = random.sample(new_ips, affect_num)
        else:
            selected_ips = new_ips

        new_ip_values = [ip_info["ip"] for ip_info in selected_ips]

        if not existing_records:
            if new_ip_values:
                ret = cloud.create_record(domain, sub_domain, new_ip_values, record_type, line, ttl)
                print(f"CREATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----VALUES: {new_ip_values}")
            return

        primary_record = existing_records[0]

        if set(existing_ips) == set(new_ip_values):
            print(f"DNS RECORDS UNCHANGED: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                  f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                  f"----VALUES: {new_ip_values}")
            return

        ret = cloud.change_record(domain, primary_record["recordId"], sub_domain, new_ip_values, record_type, line, ttl)

        print(f"BATCH UPDATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
              f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
              f"----OLD VALUES: {existing_ips} ----NEW VALUES: {new_ip_values}")

        if len(existing_records) > 1:
            for extra_record in existing_records[1:]:
                cloud.del_record(domain, extra_record["recordId"])
                print(f"CLEANUP EXTRA RECORD: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----RECORDID: {extra_record['recordId']} ----VALUE: {extra_record['value']}")
    except Exception as e:
        print(f"BATCH UPDATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
              f"----MESSAGE: {str(e)}")
        traceback.print_exc()

def changeDNS(line, s_info, c_info, domain, sub_domain, cloud):
    """修改DNS记录 - 华为云专用版本"""
    global config
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"

    # 线路映射 - 扩展支持所有线路
    lines = {
        "CM": "移动", 
        "CU": "联通", 
        "CT": "电信", 
        "ED": "教育网", 
        "TT": "铁通", 
        "PBS": "鹏博士", 
        "DEF": "默认"
    }
    line_chinese = lines[line]

    filtered_c_info, blocked_ips = filter_blacklist_ips(c_info)

    if not filtered_c_info:
        print(f"警告: 所有候选IP都在黑名单中，跳过更新 {sub_domain} - {line_chinese}")
        return

    # 华为云统一使用批量更新方式
    batch_update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                           s_info, filtered_c_info, config["ttl"], config["affect_num"])

def cleanup_extra_records(cloud, domain, sub_domain, record_type, target_lines):
    """检查指定子域名下目标线路的记录"""
    try:
        ret = cloud.get_record(domain, 100, sub_domain, record_type)

        all_records = ret["data"]["records"]

        line_records = {}
        for line in target_lines:
            line_records[line] = []

        for record in all_records:
            line_name = record.get("line", "")
            if line_name in target_lines:
                line_records[line_name].append(record)

        print(f"子域名 {sub_domain} 下 {record_type} 记录统计:")
        for line, records in line_records.items():
            print(f"  {line}: {len(records)} 条")
    except Exception as e:
        print(f"检查记录时出错: {str(e)}")

def main(cloud):
    """主函数"""
    global config, iptype
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"

    # 所有支持的线路中文名称
    all_net_lines = ["移动", "联通", "电信", "教育网", "铁通", "鹏博士", "默认"]
    
    # 线路代码映射
    line_codes = ["CM", "CU", "CT", "ED", "TT", "PBS", "DEF"]

    if len(DOMAINS) > 0:
        try:
            # 使用get_random_ips生成IP
            cfips = get_random_ips()
            if cfips == None or cfips["code"] != 200:
                print("GET IP ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) )
                return
            
            # 获取各线路的IP
            line_ips = {}
            for line_code in line_codes:
                line_ips[line_code] = cfips["info"].get(line_code, [])
                print(f"{line_code} IP数量: {len(line_ips[line_code])}")

            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    # 过滤出支持的线路
                    filtered_lines = [line for line in lines if line in line_codes]

                    if not filtered_lines:
                        print(f"子域名 {sub_domain} 没有指定有效线路，跳过")
                        continue

                    # 检查当前域名的记录
                    cleanup_extra_records(cloud, domain, sub_domain, recordType, all_net_lines)

                    # 获取当前DNS记录
                    ret = cloud.get_record(domain, 100, sub_domain, recordType)

                    # 按线路分类现有记录
                    line_info = {line: [] for line in line_codes}
                    
                    for record in ret["data"]["records"]:
                        info = {}
                        info["recordId"] = record["id"]
                        info["value"] = record["value"]

                        line_name = record["line"]
                        
                        # 将中文线路名映射回代码
                        if line_name == "移动":
                            line_info["CM"].append(info)
                        elif line_name == "联通":
                            line_info["CU"].append(info)
                        elif line_name == "电信":
                            line_info["CT"].append(info)
                        elif line_name == "教育网":
                            line_info["ED"].append(info)
                        elif line_name == "铁通":
                            line_info["TT"].append(info)
                        elif line_name == "鹏博士":
                            line_info["PBS"].append(info)
                        elif line_name == "默认":
                            line_info["DEF"].append(info)

                    # 打印当前各线路记录数量
                    print(f"子域名 {sub_domain} 当前各线路记录数量:")
                    for line_code in line_codes:
                        print(f"  {line_code}: {len(line_info[line_code])} 条")

                    # 更新指定线路的DNS记录
                    for line in filtered_lines:
                        changeDNS(line, line_info[line], line_ips[line].copy(), domain, sub_domain, cloud)

        except Exception as e:
            traceback.print_exc()  
            print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(traceback.print_exc()))

if __name__ == '__main__':
    # 初始化华为云DNS客户端
    cloud = HuaWeiApi(config["secretid"], config["secretkey"], config["region_hw"])
    
    # 处理IPv4
    if config["ipv4"] == "on":
        iptype = "v4"
        if not IPV4_CIDRS:
            print("警告: IPv4已开启但未配置IPv4 CIDR，跳过IPv4处理")
        else:
            main(cloud)
    
    # 处理IPv6
    if config["ipv6"] == "on":
        iptype = "v6"
        if not IPV6_CIDRS:
            print("警告: IPv6已开启但未配置IPv6 CIDR，跳过IPv6处理")
        else:
            main(cloud)