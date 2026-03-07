#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, time, random, traceback
import ipaddress

# 从环境变量获取配置（这些是原有的，用于DNS更新认证）
config = json.loads(os.environ["CONFIG"])
#CM:移动 CU:联通 CT:电信  AB:境外 DEF:默认
DOMAINS = json.loads(os.environ["DOMAINS"])

# ==================== 从环境变量获取CIDR配置 ====================
def get_cidrs_from_env(env_var_name):
    """
    从环境变量获取CIDR列表
    环境变量中的CIDR可以是每行一个，或者用逗号分隔
    """
    cidr_str = os.environ.get(env_var_name, "")
    if not cidr_str:
        return []
    
    cidrs = []
    for line in cidr_str.split('\n'):
        for cidr in line.split(','):
            cidr = cidr.strip()
            if cidr and not cidr.startswith('#'):
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
CUSTOM_BLACKLIST = get_cidrs_from_env("CUSTOM_BLACKLIST")

IP_BLACKLIST_CIDR = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "127.0.0.0/8",
    "0.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

if CUSTOM_BLACKLIST:
    IP_BLACKLIST_CIDR.extend(CUSTOM_BLACKLIST)
    print(f"已添加 {len(CUSTOM_BLACKLIST)} 个自定义黑名单网段")

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
        except Exception as e:
            print(f"警告: 解析CIDR '{cidr}' 时发生错误: {str(e)}")

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
    except Exception:
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

compile_blacklist()

# ==================== 从CIDR生成随机IP的函数 ====================

def generate_random_ip_from_cidr(cidr):
    """
    从CIDR中随机生成一个可用的IP地址
    排除网络地址和广播地址
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        num_hosts = network.num_addresses
        
        if network.version == 4:
            if num_hosts <= 2:
                print(f"警告: CIDR {cidr} 主机位不足，无法分配可用IP")
                return None
            host_index = random.randint(1, num_hosts - 2)
            ip = network.network_address + host_index
        else:
            if num_hosts <= 1:
                print(f"警告: CIDR {cidr} 主机位不足，无法分配可用IP")
                return None
            host_index = random.randint(1, num_hosts - 1)
            ip = network.network_address + host_index
        
        return str(ip)
    except Exception as e:
        print(f"从CIDR {cidr} 生成IP时出错: {str(e)}")
        return None

def generate_random_ips_from_cidrs(cidr_list, count, is_v6=False):
    """
    从CIDR列表中随机生成指定数量的IP
    """
    if not cidr_list:
        print(f"警告: {'IPv6' if is_v6 else 'IPv4'} CIDR列表为空")
        return []
    
    ip_infos = []
    attempts = 0
    max_attempts = count * 20
    
    while len(ip_infos) < count and attempts < max_attempts:
        attempts += 1
        cidr = random.choice(cidr_list)
        ip = generate_random_ip_from_cidr(cidr)
        
        if ip and not is_ip_blacklisted(ip):
            ip_info = {
                "ip": ip,
                "latency": random.randint(10, 200),
                "speed": random.randint(10, 100),
                "avgScore": random.randint(60, 100),
                "downloadSpeed": random.randint(10, 100),
                "ydScore": random.randint(60, 100),
                "ltScore": random.randint(60, 100),
                "dxScore": random.randint(60, 100),
                "ydLatencyAvg": random.randint(10, 200),
                "ltLatencyAvg": random.randint(10, 200),
                "dxLatencyAvg": random.randint(10, 200)
            }
            
            if ip not in [existing["ip"] for existing in ip_infos]:
                ip_infos.append(ip_info)
    
    print(f"从 {len(cidr_list)} 个 {'IPv6' if is_v6 else 'IPv4'} CIDR中生成了 {len(ip_infos)} 个IP")
    return ip_infos

def get_random_ips():
    """
    从CIDR生成IP信息
    """
    generated_ips = {
        "v4": {"CM": [], "CU": [], "CT": []},
        "v6": {"CM": [], "CU": [], "CT": []}
    }
    
    if IPV4_CIDRS:
        ipv4_ips = generate_random_ips_from_cidrs(IPV4_CIDRS, IP_COUNT_PER_ISP * 3, is_v6=False)
        for i, isp in enumerate(["CM", "CU", "CT"]):
            start_idx = i * IP_COUNT_PER_ISP
            end_idx = start_idx + IP_COUNT_PER_ISP
            if start_idx < len(ipv4_ips):
                generated_ips["v4"][isp] = ipv4_ips[start_idx:end_idx]
    
    if IPV6_CIDRS:
        ipv6_ips = generate_random_ips_from_cidrs(IPV6_CIDRS, IP_COUNT_PER_ISP * 3, is_v6=True)
        for i, isp in enumerate(["CM", "CU", "CT"]):
            start_idx = i * IP_COUNT_PER_ISP
            end_idx = start_idx + IP_COUNT_PER_ISP
            if start_idx < len(ipv6_ips):
                generated_ips["v6"][isp] = ipv6_ips[start_idx:end_idx]
    
    total_ips = sum(len(generated_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
    print(f"当前类型 {iptype} 总共生成了 {total_ips} 个IP（已过滤黑名单）")
    
    result = {
        "code": 200,
        "info": {
            "CM": generated_ips[iptype]["CM"],
            "CU": generated_ips[iptype]["CU"],
            "CT": generated_ips[iptype]["CT"]
        }
    }
    
    return result

# ==================== 华为云DNS更新代码 ====================

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
    """获取IP信息的排序键值"""
    try:
        speed = safe_float_conversion(ip_info.get("speed"))
        if speed > 0:
            return speed

        avg_score = safe_float_conversion(ip_info.get("avgScore"))
        if avg_score > 0:
            return avg_score

        download_speed = safe_float_conversion(ip_info.get("downloadSpeed"))
        if download_speed > 0:
            return download_speed

        if isp == "CM":
            yd_score = safe_float_conversion(ip_info.get("ydScore"))
            if yd_score > 0:
                return yd_score
            latency = safe_float_conversion(ip_info.get("ydLatencyAvg"))
            if latency > 0:
                return -latency
        elif isp == "CU":
            lt_score = safe_float_conversion(ip_info.get("ltScore"))
            if lt_score > 0:
                return lt_score
            latency = safe_float_conversion(ip_info.get("ltLatencyAvg"))
            if latency > 0:
                return -latency
        elif isp == "CT":
            dx_score = safe_float_conversion(ip_info.get("dxScore"))
            if dx_score > 0:
                return dx_score
            latency = safe_float_conversion(ip_info.get("dxLatencyAvg"))
            if latency > 0:
                return -latency

        latency = safe_float_conversion(ip_info.get("latency"))
        if latency > 0:
            return -latency

        return 0.0
    except Exception:
        return 0.0

def batch_update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl, affect_num):
    """批量更新华为云DNS记录"""
    try:
        existing_ips = [record["value"] for record in existing_records]
        filtered_ips, blocked_ips = filter_blacklist_ips(new_ips)

        if not filtered_ips:
            print(f"警告: 所有候选IP都在黑名单中，跳过更新")
            return

        if len(filtered_ips) > affect_num:
            line_isp = None
            if line == "移动":
                line_isp = "CM"
            elif line == "联通":
                line_isp = "CU"
            elif line == "电信":
                line_isp = "CT"
            
            filtered_ips = sorted(
                filtered_ips, 
                key=lambda x: get_sort_key(x, line_isp),
                reverse=True
            )[:affect_num]

        new_ip_values = [ip_info["ip"] for ip_info in filtered_ips]

        if not existing_records:
            if new_ip_values:
                ret = cloud.create_record(domain, sub_domain, new_ip_values, record_type, line, ttl)
                if ret and ret.get("code") == 0:
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

        if ret and ret.get("code") == 0:
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

def cleanup_extra_records(cloud, domain, sub_domain, record_type, target_lines):
    """清理指定子域名下目标线路的多余记录"""
    try:
        ret = cloud.get_record(domain, 100, sub_domain, record_type)
        if ret.get("code") != 0:
            return

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

    all_lines = ["移动", "联通", "电信", "境外", "默认"]

    if len(DOMAINS) > 0:
        try:
            cfips = get_random_ips()
            if cfips == None or cfips["code"] != 200:
                print("GET CLOUDFLARE IP ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) )
                return
            cf_cmips = cfips["info"]["CM"]
            cf_cuips = cfips["info"]["CU"]
            cf_ctips = cfips["info"]["CT"]
            
            # 创建合并的IP池（用于境外和默认线路）
            all_ips = []
            seen_ips = set()
            for ip_info in cf_cmips + cf_cuips + cf_ctips:
                if ip_info["ip"] not in seen_ips:
                    seen_ips.add(ip_info["ip"])
                    all_ips.append(ip_info)

            print(f"当前IP数量 - 移动: {len(cf_cmips)}, 联通: {len(cf_cuips)}, 电信: {len(cf_ctips)}, 合并去重后: {len(all_ips)}")

            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    filtered_lines = [line for line in lines if line in ["CM", "CU", "CT", "AB", "DEF"]]

                    if not filtered_lines:
                        print(f"子域名 {sub_domain} 没有指定线路，跳过")
                        continue

                    cleanup_extra_records(cloud, domain, sub_domain, recordType, all_lines)

                    temp_cf_cmips = cf_cmips.copy()
                    temp_cf_cuips = cf_cuips.copy()
                    temp_cf_ctips = cf_ctips.copy()
                    temp_all_ips = all_ips.copy()

                    ret = cloud.get_record(domain, 100, sub_domain, recordType)
                    if ret.get("code") == 0:
                        # 初始化所有线路的记录列表
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        ab_info = []
                        def_info = []

                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"]
                            info["value"] = record["value"]
                            line_name = record.get("line", "")

                            if line_name == "移动":
                                cm_info.append(info)
                            elif line_name == "联通":
                                cu_info.append(info)
                            elif line_name == "电信":
                                ct_info.append(info)
                            elif line_name == "境外":
                                ab_info.append(info)
                            elif line_name == "默认":
                                def_info.append(info)

                        print(f"当前记录数量 - 移动: {len(cm_info)}, 联通: {len(cu_info)}, 电信: {len(ct_info)}, 境外: {len(ab_info)}, 默认: {len(def_info)}")

                        for line in filtered_lines:
                            if line == "CM":
                                batch_update_huawei_dns(cloud, domain, sub_domain, recordType, "移动", 
                                                       cm_info, temp_cf_cmips, config["ttl"], config["affect_num"])
                            elif line == "CU":
                                batch_update_huawei_dns(cloud, domain, sub_domain, recordType, "联通", 
                                                       cu_info, temp_cf_cuips, config["ttl"], config["affect_num"])
                            elif line == "CT":
                                batch_update_huawei_dns(cloud, domain, sub_domain, recordType, "电信", 
                                                       ct_info, temp_cf_ctips, config["ttl"], config["affect_num"])
                            elif line == "AB":
                                batch_update_huawei_dns(cloud, domain, sub_domain, recordType, "境外", 
                                                       ab_info, temp_cf_ctips, config["ttl"], config["affect_num"])
                            elif line == "DEF":
                                batch_update_huawei_dns(cloud, domain, sub_domain, recordType, "默认", 
                                                       def_info, temp_cf_ctips, config["ttl"], config["affect_num"])

        except Exception as e:
            traceback.print_exc()  
            print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(traceback.print_exc()))

if __name__ == '__main__':
    # 只保留华为云DNS客户端
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
