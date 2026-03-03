#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, requests, time, base64, shutil, random, traceback
import ipaddress

# 从环境变量获取配置（这些是原有的，用于DNS更新认证）
config = json.loads(os.environ["CONFIG"])
#CM:移动 CU:联通 CT:电信  AB:境外 DEF:默认
DOMAINS = json.loads(os.environ["DOMAINS"])
#获取服务商信息
provider_data = json.loads(os.environ["PROVIDER"])

# ==================== 从环境变量获取CIDR配置 ====================
# 需要在GitHub Secrets中设置以下变量：
# IPV4_CIDRS: IPv4 CIDR列表，每行一个CIDR（可选，如果ipv4开启则需要）
# IPV6_CIDRS: IPv6 CIDR列表，每行一个CIDR（可选，如果ipv6开启则需要）
# IP_COUNT_PER_ISP: 每个运营商生成的IP数量（可选，默认20）
# CUSTOM_BLACKLIST: 自定义黑名单CIDR（可选）

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
    返回IP信息列表，格式与原有API兼容
    """
    if not cidr_list:
        print(f"警告: {'IPv6' if is_v6 else 'IPv4'} CIDR列表为空")
        return []
    
    ip_infos = []
    attempts = 0
    max_attempts = count * 20  # 防止无限循环
    
    while len(ip_infos) < count and attempts < max_attempts:
        attempts += 1
        
        # 随机选择一个CIDR
        cidr = random.choice(cidr_list)
        
        # 生成随机IP
        ip = generate_random_ip_from_cidr(cidr)
        
        if ip and not is_ip_blacklisted(ip):
            # 创建与原有API兼容的IP信息格式
            # 生成一些随机但合理的性能数据
            ip_info = {
                "ip": ip,
                "latency": random.randint(10, 200),      # 延迟 10-200ms
                "speed": random.randint(10, 100),        # 速度 10-100 Mbps
                "avgScore": random.randint(60, 100),      # 平均分 60-100
                "downloadSpeed": random.randint(10, 100), # 下载速度
                # 添加各运营商的评分（可以根据IP类型生成不同的值）
                "ydScore": random.randint(60, 100),       # 移动评分
                "ltScore": random.randint(60, 100),       # 联通评分
                "dxScore": random.randint(60, 100),       # 电信评分
                # 添加各运营商的延迟
                "ydLatencyAvg": random.randint(10, 200),
                "ltLatencyAvg": random.randint(10, 200),
                "dxLatencyAvg": random.randint(10, 200)
            }
            
            # 检查是否重复
            if ip not in [existing["ip"] for existing in ip_infos]:
                ip_infos.append(ip_info)
    
    print(f"从 {len(cidr_list)} 个 {'IPv6' if is_v6 else 'IPv4'} CIDR中生成了 {len(ip_infos)} 个IP")
    return ip_infos

def get_random_ips():
    """
    从CIDR生成IP信息
    替代原来的get_optimization_ip函数
    """
    # 存储生成的IP信息
    generated_ips = {
        "v4": {"CM": [], "CU": [], "CT": []},
        "v6": {"CM": [], "CU": [], "CT": []}
    }
    
    # 从IPv4 CIDR生成IP
    if IPV4_CIDRS:
        ipv4_ips = generate_random_ips_from_cidrs(IPV4_CIDRS, IP_COUNT_PER_ISP * 3, is_v6=False)
        # 平均分配给三个运营商
        for i, isp in enumerate(["CM", "CU", "CT"]):
            start_idx = i * IP_COUNT_PER_ISP
            end_idx = start_idx + IP_COUNT_PER_ISP
            if start_idx < len(ipv4_ips):
                generated_ips["v4"][isp] = ipv4_ips[start_idx:end_idx]
    
    # 从IPv6 CIDR生成IP
    if IPV6_CIDRS:
        ipv6_ips = generate_random_ips_from_cidrs(IPV6_CIDRS, IP_COUNT_PER_ISP * 3, is_v6=True)
        # 平均分配给三个运营商
        for i, isp in enumerate(["CM", "CU", "CT"]):
            start_idx = i * IP_COUNT_PER_ISP
            end_idx = start_idx + IP_COUNT_PER_ISP
            if start_idx < len(ipv6_ips):
                generated_ips["v6"][isp] = ipv6_ips[start_idx:end_idx]
    
    # 为当前iptype统计
    total_ips = sum(len(generated_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
    print(f"当前类型 {iptype} 总共生成了 {total_ips} 个IP（已过滤黑名单）")
    
    # 构建返回数据，保持与原API相同的格式
    result = {
        "code": 200,
        "info": {
            "CM": generated_ips[iptype]["CM"],
            "CU": generated_ips[iptype]["CU"],
            "CT": generated_ips[iptype]["CT"]
        }
    }
    
    return result

# ==================== 原有的DNS更新代码（保持不变）====================

from dns.qCloud import QcloudApiv3
from dns.aliyun import AliApi
from dns.huawei import HuaWeiApi

def safe_float_conversion(value, default=0.0):
    """安全地将值转换为浮点数"""
    try:
        if value is None:
            return default
        return float(value)
    except (ValueError, TypeError):
        return default

def get_sort_key(ip_info, isp=None):
    """获取IP信息的排序键值，用于lambda表达式"""
    try:
        # 优先使用speed字段
        speed = safe_float_conversion(ip_info.get("speed"))
        if speed > 0:
            return speed

        # 其次使用avgScore
        avg_score = safe_float_conversion(ip_info.get("avgScore"))
        if avg_score > 0:
            return avg_score

        # 然后使用downloadSpeed
        download_speed = safe_float_conversion(ip_info.get("downloadSpeed"))
        if download_speed > 0:
            return download_speed

        # 如果有指定运营商，使用对应的运营商评分
        if isp == "CM":
            yd_score = safe_float_conversion(ip_info.get("ydScore"))
            if yd_score > 0:
                return yd_score
        elif isp == "CU":
            lt_score = safe_float_conversion(ip_info.get("ltScore"))
            if lt_score > 0:
                return lt_score
        elif isp == "CT":
            dx_score = safe_float_conversion(ip_info.get("dxScore"))
            if dx_score > 0:
                return dx_score

        # 使用延迟（越低越好，所以取负值）
        if isp == "CM":
            latency = safe_float_conversion(ip_info.get("ydLatencyAvg"))
            if latency > 0:
                return -latency
        elif isp == "CU":
            latency = safe_float_conversion(ip_info.get("ltLatencyAvg"))
            if latency > 0:
                return -latency
        elif isp == "CT":
            latency = safe_float_conversion(ip_info.get("dxLatencyAvg"))
            if latency > 0:
                return -latency

        # 最后使用通用延迟
        latency = safe_float_conversion(ip_info.get("latency"))
        if latency > 0:
            return -latency

        return 0.0
    except Exception:
        return 0.0

def line_to_isp(line_chinese):
    """将中文线路名称转换为ISP代码"""
    line_map = {
        "移动": "CM",
        "联通": "CU", 
        "电信": "CT"
    }
    return line_map.get(line_chinese, None)

def batch_update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl, affect_num):
    """批量更新华为云DNS记录"""
    try:
        existing_ips = [record["value"] for record in existing_records]
        filtered_ips, blocked_ips = filter_blacklist_ips(new_ips)

        if not filtered_ips:
            print(f"警告: 所有候选IP都在黑名单中，跳过更新")
            return

        if len(filtered_ips) > affect_num:
            filtered_ips = sorted(
                filtered_ips, 
                key=lambda x: get_sort_key(x, line_to_isp(line)),
                reverse=True
            )[:affect_num]

        new_ip_values = [ip_info["ip"] for ip_info in filtered_ips]

        if not existing_records:
            if new_ip_values:
                ret = cloud.create_record(domain, sub_domain, new_ip_values, record_type, line, ttl)
                if ret and (config["dns_server"] != 1 or ret.get("code") == 0):
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

        if ret and (config["dns_server"] != 1 or ret.get("code") == 0):
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
    """修改DNS记录"""
    global config
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"

    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line_chinese = lines[line]

    filtered_c_info, blocked_ips = filter_blacklist_ips(c_info)

    if not filtered_c_info:
        print(f"警告: 所有候选IP都在黑名单中，跳过更新 {sub_domain} - {line_chinese}")
        return

    if config["dns_server"] == 3:
        new_ips = [ip_info for ip_info in filtered_c_info]
        batch_update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                               s_info, new_ips, config["ttl"], config["affect_num"])
        return

    try:
        create_num = config["affect_num"] - len(s_info)
        if create_num == 0:
            for info in s_info:
                if len(filtered_c_info) == 0:
                    break
                filtered_c_info_sorted = sorted(filtered_c_info, key=lambda x: get_sort_key(x, line), reverse=True)
                cf_ip_info = filtered_c_info_sorted[0]
                filtered_c_info.remove(cf_ip_info)
                cf_ip = cf_ip_info["ip"]

                if cf_ip in str(s_info):
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, recordType, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip )
                else:
                    print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
        elif create_num > 0:
            for i in range(create_num):
                if len(filtered_c_info) == 0:
                    break
                filtered_c_info_sorted = sorted(filtered_c_info, key=lambda x: get_sort_key(x, line), reverse=True)
                cf_ip_info = filtered_c_info_sorted[0]
                filtered_c_info.remove(cf_ip_info)
                cf_ip = cf_ip_info["ip"]

                if cf_ip in str(s_info):
                    continue
                ret = cloud.create_record(domain, sub_domain, cf_ip, recordType, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CREATE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----VALUE: " + cf_ip )
                else:
                    print("CREATE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
        else:
            for info in s_info:
                if create_num == 0 or len(filtered_c_info) == 0:
                    break
                filtered_c_info_sorted = sorted(filtered_c_info, key=lambda x: get_sort_key(x, line), reverse=True)
                cf_ip_info = filtered_c_info_sorted[0]
                filtered_c_info.remove(cf_ip_info)
                cf_ip = cf_ip_info["ip"]

                if cf_ip in str(s_info):
                    create_num += 1
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, recordType, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip )
                else:
                    print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
                create_num += 1
    except Exception as e:
        print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(traceback.print_exc()))

def cleanup_extra_records(cloud, domain, sub_domain, record_type, target_lines):
    """清理指定子域名下目标线路的多余记录"""
    try:
        ret = cloud.get_record(domain, 100, sub_domain, record_type)
        if config["dns_server"] == 1 and ret["code"] != 0:
            return

        all_records = ret["data"]["records"]

        line_records = {}
        for line in target_lines:
            line_records[line] = []

        for record in all_records:
            line_name = ""
            if config["dns_server"] == 1:
                line_name = record.get("line", "")
            elif config["dns_server"] == 2:
                line_name = record.get("Line", "")
            elif config["dns_server"] == 3:
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

    three_net_lines = ["移动", "联通", "电信"]

    if len(DOMAINS) > 0:
        try:
            # 使用新的get_random_ips替代原来的get_optimization_ip
            cfips = get_random_ips()
            if cfips == None or cfips["code"] != 200:
                print("GET CLOUDFLARE IP ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) )
                return
            cf_cmips = cfips["info"]["CM"]
            cf_cuips = cfips["info"]["CU"]
            cf_ctips = cfips["info"]["CT"]

            print(f"当前IP数量（已过滤黑名单） - 移动: {len(cf_cmips)}, 联通: {len(cf_cuips)}, 电信: {len(cf_ctips)}")

            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    filtered_lines = [line for line in lines if line in ["CM", "CU", "CT"]]

                    if not filtered_lines:
                        print(f"子域名 {sub_domain} 没有指定三网线路，跳过")
                        continue

                    cleanup_extra_records(cloud, domain, sub_domain, recordType, three_net_lines)

                    temp_cf_cmips = cf_cmips.copy()
                    temp_cf_cuips = cf_cuips.copy()
                    temp_cf_ctips = cf_ctips.copy()

                    ret = cloud.get_record(domain, 100, sub_domain, recordType)
                    if config["dns_server"] != 1 or ret["code"] == 0:
                        if config["dns_server"] == 1 and "Free" in ret["data"]["domain"]["grade"] and config["affect_num"] > 2:
                            config["affect_num"] = 2

                        cm_info = []
                        cu_info = []
                        ct_info = []

                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"] if config["dns_server"] != 2 else record["RecordId"]
                            info["value"] = record["value"]

                            line_name = ""
                            if config["dns_server"] == 1:
                                line_name = record["line"]
                            elif config["dns_server"] == 2:
                                line_name = record["Line"]
                            elif config["dns_server"] == 3:
                                line_name = record["line"]

                            if line_name == "移动":
                                cm_info.append(info)
                            elif line_name == "联通":
                                cu_info.append(info)
                            elif line_name == "电信":
                                ct_info.append(info)

                        print(f"当前三网记录数量 - 移动: {len(cm_info)}, 联通: {len(cu_info)}, 电信: {len(ct_info)}")

                        for line in filtered_lines:
                            if line == "CM":
                                changeDNS("CM", cm_info, temp_cf_cmips, domain, sub_domain, cloud)
                            elif line == "CU":
                                changeDNS("CU", cu_info, temp_cf_cuips, domain, sub_domain, cloud)
                            elif line == "CT":
                                changeDNS("CT", ct_info, temp_cf_ctips, domain, sub_domain, cloud)

        except Exception as e:
            traceback.print_exc()  
            print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(traceback.print_exc()))

if __name__ == '__main__':
    # 初始化DNS客户端（使用原有的认证信息）
    if config["dns_server"] == 1:
        cloud = QcloudApiv3(config["secretid"], config["secretkey"])
    elif config["dns_server"] == 2:
        cloud = AliApi(config["secretid"], config["secretkey"], config["region_ali"])
    elif config["dns_server"] == 3:
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
