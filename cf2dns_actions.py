#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, requests, time, base64, shutil, random, traceback
import ipaddress

# 生成随机时间，范围在10到150之间
#random_time = random.uniform(10, 100)
#print("本次将等待{}秒执行".format(random_time))
# 延迟执行随机时间
#time.sleep(random_time)

from dns.qCloud import QcloudApiv3 # QcloudApiv3 DNSPod 的 API 更新了 By github@z0z0r4
from dns.aliyun import AliApi
from dns.huawei import HuaWeiApi

config = json.loads(os.environ["CONFIG"])
#CM:移动 CU:联通 CT:电信  AB:境外 DEF:默认
#修改需要更改的dnspod域名和子域名
DOMAINS = json.loads(os.environ["DOMAINS"])
#获取服务商信息
provider_data = json.loads(os.environ["PROVIDER"])

# 新的API地址
NEW_API_URL = "https://api.4ce.cn/api/bestCFIP"
# 添加VPS789 API地址
VPS789_API_URL = "https://vps789.com/public/sum/cfIpApi"

# ==================== IP黑名单配置（手动编码）====================
# 支持CIDR格式，可以添加IPv4和IPv6网段
# 格式：["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32", "1.1.1.1/32"]
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
    "255.255.255.255/32", # 屏蔽广播地址
    "::1/128",         # 屏蔽IPv6回环地址
    "fc00::/7",        # 屏蔽唯一本地地址
    "fe80::/10",       # 屏蔽链路本地地址
    "ff00::/8",        # 屏蔽组播地址

    "172.64.159.79/32"
]

# 编译IP黑名单网络对象，提高匹配效率
IP_BLACKLIST_NETWORKS = []

def compile_blacklist():
    """
    编译IP黑名单CIDR列表为ipaddress网络对象
    """
    global IP_BLACKLIST_NETWORKS
    IP_BLACKLIST_NETWORKS = []
    
    for cidr in IP_BLACKLIST_CIDR:
        try:
            # 尝试解析为IPv4或IPv6网络
            network = ipaddress.ip_network(cidr, strict=False)
            IP_BLACKLIST_NETWORKS.append(network)
            print(f"添加黑名单网段: {cidr} ({'IPv4' if network.version == 4 else 'IPv6'})")
        except ValueError as e:
            print(f"警告: CIDR格式错误 '{cidr}': {str(e)}")
        except Exception as e:
            print(f"警告: 解析CIDR '{cidr}' 时发生未知错误: {str(e)}")
    
    print(f"IP黑名单初始化完成，共加载 {len(IP_BLACKLIST_NETWORKS)} 个网段")

def is_ip_blacklisted(ip):
    """
    检查IP是否在黑名单中
    支持IPv4和IPv6
    """
    try:
        # 尝试解析IP地址
        ip_addr = ipaddress.ip_address(ip)
        
        # 检查是否匹配任何黑名单网段
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
    """
    过滤掉黑名单中的IP
    返回过滤后的IP列表和被过滤的IP列表
    """
    filtered_ips = []
    blocked_ips = []
    
    for ip_info in ip_list:
        # 处理不同格式的IP信息
        if isinstance(ip_info, dict):
            ip = ip_info.get("ip", "")
        elif isinstance(ip_info, str):
            ip = ip_info
            ip_info = {"ip": ip}  # 转换为统一格式
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
# ==================== IP黑名单配置结束 ====================

def safe_float_conversion(value, default=0.0):
    """
    安全地将值转换为浮点数
    """
    try:
        if value is None:
            return default
        return float(value)
    except (ValueError, TypeError):
        return default

def get_sort_key(ip_info, isp=None):
    """
    获取IP信息的排序键值，用于lambda表达式
    根据不同的运营商使用对应的评分
    """
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
                return -latency  # 延迟越低越好
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

def get_optimization_ip():
    """
    从多个API获取IP信息并合并
    原API：通过provider_data中的配置获取
    新API：https://api.4ce.cn/api/bestCFIP
    VPS789 API：https://vps789.com/public/sum/cfIpApi
    """
    try:
        # 存储所有版本的IP信息
        merged_ips = {
            "v4": {"CM": [], "CU": [], "CT": []},
            "v6": {"CM": [], "CU": [], "CT": []}
        }
        
        headers = {'Content-Type': 'application/json'}
        
        # 1. 从原API获取IP信息（获取v4和v6两种类型）
        try:
            for current_type in ["v4", "v6"]:
                data = {"key": config["key"], "type": current_type}
                provider = [item for item in provider_data if item['id'] == config["data_server"]][0]
                response = requests.post(provider['get_ip_url'], json=data, headers=headers, timeout=10)
                if response.status_code == 200:
                    old_data = response.json()
                    if old_data and old_data.get("code") == 200:
                        for isp in ["CM", "CU", "CT"]:
                            if isp in old_data["info"]:
                                for ip_info in old_data["info"][isp]:
                                    # 确保ip_info是字典格式
                                    if isinstance(ip_info, str):
                                        ip_info = {"ip": ip_info}
                                    elif isinstance(ip_info, dict) and "ip" not in ip_info:
                                        # 如果字典中没有ip字段，尝试其他字段
                                        if "value" in ip_info:
                                            ip_info["ip"] = ip_info["value"]
                                    
                                    # 过滤黑名单IP
                                    if not is_ip_blacklisted(ip_info.get("ip", "")):
                                        merged_ips[current_type][isp].append(ip_info)
                print(f"从原API获取到 {current_type} IP: {sum(len(merged_ips[current_type][isp]) for isp in ['CM','CU','CT'])} 个")
        except Exception as e:
            print(f"从原API获取IP失败: {str(e)}")
        
        # 2. 从新API (4ce.cn) 获取IP信息
        try:
            response = requests.get(NEW_API_URL, timeout=10)
            if response.status_code == 200:
                new_data = response.json()
                if new_data and new_data.get("success") and "data" in new_data:
                    for ip_version in ["v4", "v6"]:
                        if ip_version in new_data["data"]:
                            for isp in ["CM", "CU", "CT"]:
                                if isp in new_data["data"][ip_version]:
                                    for ip_info in new_data["data"][ip_version][isp]:
                                        # 转换新API的数据格式以匹配原API
                                        converted_info = {
                                            "ip": ip_info["ip"],
                                            "name": ip_info.get("name", ""),
                                            "colo": ip_info.get("colo", ""),
                                            "latency": ip_info.get("latency", 0),
                                            "speed": ip_info.get("speed", 0),
                                            "uptime": ip_info.get("uptime", "")
                                        }
                                        # 过滤黑名单IP
                                        if not is_ip_blacklisted(ip_info["ip"]):
                                            merged_ips[ip_version][isp].append(converted_info)
                    print(f"从4ce.cn API获取到IP: v4: {sum(len(merged_ips['v4'][isp]) for isp in ['CM','CU','CT'])}, v6: {sum(len(merged_ips['v6'][isp]) for isp in ['CM','CU','CT'])}")
        except Exception as e:
            print(f"从4ce.cn API获取IP失败: {str(e)}")
        
        # 3. 从VPS789 API获取IP信息
        try:
            response = requests.get(VPS789_API_URL, timeout=10)
            if response.status_code == 200:
                vps789_data = response.json()
                if vps789_data and vps789_data.get("code") == 0 and "data" in vps789_data:
                    # 处理V4数据
                    if "v4" in vps789_data["data"]:
                        for isp in ["CM", "CU", "CT"]:
                            if isp in vps789_data["data"]["v4"]:
                                for ip_info in vps789_data["data"]["v4"][isp]:
                                    converted_info = {
                                        "ip": ip_info["ip"],
                                        "ydLatencyAvg": ip_info.get("ydLatencyAvg", 0),
                                        "ydPkgLostRateAvg": ip_info.get("ydPkgLostRateAvg", 0),
                                        "ltLatencyAvg": ip_info.get("ltLatencyAvg", 0),
                                        "ltPkgLostRateAvg": ip_info.get("ltPkgLostRateAvg", 0),
                                        "dxLatencyAvg": ip_info.get("dxLatencyAvg", 0),
                                        "dxPkgLostRateAvg": ip_info.get("dxPkgLostRateAvg", 0),
                                        "downloadSpeed": ip_info.get("downloadSpeed", 0),
                                        "avgScore": ip_info.get("avgScore", 0),
                                        "ydScore": ip_info.get("ydScore", 0),
                                        "dxScore": ip_info.get("dxScore", 0),
                                        "ltScore": ip_info.get("ltScore", 0),
                                        "createdTime": ip_info.get("createdTime", "")
                                    }
                                    # 过滤黑名单IP
                                    if not is_ip_blacklisted(ip_info["ip"]):
                                        merged_ips["v4"][isp].append(converted_info)
                    
                    # 处理V6数据
                    if "v6" in vps789_data["data"]:
                        for isp in ["CM", "CU", "CT"]:
                            if isp in vps789_data["data"]["v6"]:
                                for ip_info in vps789_data["data"]["v6"][isp]:
                                    converted_info = {
                                        "ip": ip_info["ip"],
                                        "ydLatencyAvg": ip_info.get("ydLatencyAvg", 0),
                                        "ydPkgLostRateAvg": ip_info.get("ydPkgLostRateAvg", 0),
                                        "ltLatencyAvg": ip_info.get("ltLatencyAvg", 0),
                                        "ltPkgLostRateAvg": ip_info.get("ltPkgLostRateAvg", 0),
                                        "dxLatencyAvg": ip_info.get("dxLatencyAvg", 0),
                                        "dxPkgLostRateAvg": ip_info.get("dxPkgLostRateAvg", 0),
                                        "downloadSpeed": ip_info.get("downloadSpeed", 0),
                                        "avgScore": ip_info.get("avgScore", 0),
                                        "ydScore": ip_info.get("ydScore", 0),
                                        "dxScore": ip_info.get("dxScore", 0),
                                        "ltScore": ip_info.get("ltScore", 0),
                                        "createdTime": ip_info.get("createdTime", "")
                                    }
                                    # 过滤黑名单IP
                                    if not is_ip_blacklisted(ip_info["ip"]):
                                        merged_ips["v6"][isp].append(converted_info)
                    
                    # 处理AllAvg数据（如果有）
                    if "AllAvg" in vps789_data["data"]:
                        for ip_info in vps789_data["data"]["AllAvg"]:
                            converted_info = {
                                "ip": ip_info["ip"],
                                "ydLatencyAvg": ip_info.get("ydLatencyAvg", 0),
                                "ydPkgLostRateAvg": ip_info.get("ydPkgLostRateAvg", 0),
                                "ltLatencyAvg": ip_info.get("ltLatencyAvg", 0),
                                "ltPkgLostRateAvg": ip_info.get("ltPkgLostRateAvg", 0),
                                "dxLatencyAvg": ip_info.get("dxLatencyAvg", 0),
                                "dxPkgLostRateAvg": ip_info.get("dxPkgLostRateAvg", 0),
                                "downloadSpeed": ip_info.get("downloadSpeed", 0),
                                "avgScore": ip_info.get("avgScore", 0),
                                "ydScore": ip_info.get("ydScore", 0),
                                "dxScore": ip_info.get("dxScore", 0),
                                "ltScore": ip_info.get("ltScore", 0),
                                "createdTime": ip_info.get("createdTime", "")
                            }
                            # 过滤黑名单IP
                            if not is_ip_blacklisted(ip_info["ip"]):
                                # 将AllAvg的IP添加到所有运营商（v4和v6都需要判断）
                                ip_type = "v6" if ":" in ip_info["ip"] else "v4"
                                for isp in ["CM", "CU", "CT"]:
                                    merged_ips[ip_type][isp].append(converted_info)
                    
                    print(f"从VPS789 API获取到IP: v4: {sum(len(merged_ips['v4'][isp]) for isp in ['CM','CU','CT'])}, v6: {sum(len(merged_ips['v6'][isp]) for isp in ['CM','CU','CT'])}")
        except Exception as e:
            print(f"从VPS789 API获取IP失败: {str(e)}")
        
        # 4. 为每个版本和运营商去重（基于IP地址，并合并数据）
        for version in ["v4", "v6"]:
            for isp in ["CM", "CU", "CT"]:
                seen_ips = {}
                unique_ips = []
                for ip_info in merged_ips[version][isp]:
                    ip = ip_info.get("ip", "")
                    if ip:
                        if ip not in seen_ips:
                            seen_ips[ip] = ip_info
                            unique_ips.append(ip_info)
                        else:
                            # 合并数据，保留非空值
                            existing = seen_ips[ip]
                            for key, value in ip_info.items():
                                if key != "ip" and value and (key not in existing or not existing[key]):
                                    existing[key] = value
                merged_ips[version][isp] = unique_ips
        
        # 5. 按速度或分数排序（使用严谨的排序函数）
        for version in ["v4", "v6"]:
            for isp in ["CM", "CU", "CT"]:
                # 使用更严谨的排序，降序排列（值越大越好）
                merged_ips[version][isp].sort(
                    key=lambda x, isp=isp: get_sort_key(x, isp),
                    reverse=True
                )
        
        # 6. 为当前iptype统计
        total_ips = sum(len(merged_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
        print(f"当前类型 {iptype} 总共获取到 {total_ips} 个IP（已过滤黑名单）")
        if total_ips > 0:
            for isp in ["CM", "CU", "CT"]:
                if merged_ips[iptype][isp]:
                    best_ip = merged_ips[iptype][isp][0]['ip']
                    best_score = get_sort_key(merged_ips[iptype][isp][0], isp)
                    print(f"  {isp}: {len(merged_ips[iptype][isp])} 个 (最佳IP: {best_ip}, 评分: {best_score:.2f})")
        
        # 7. 构建返回数据，保持与原API相同的格式
        result = {
            "code": 200,
            "info": {
                "CM": merged_ips[iptype]["CM"],
                "CU": merged_ips[iptype]["CU"],
                "CT": merged_ips[iptype]["CT"]
            }
        }
        
        return result
        
    except Exception as e:
        print(f"获取优化IP失败: {str(e)}")
        traceback.print_exc()
        return None

def batch_update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl, affect_num):
    """
    批量更新华为云DNS记录
    利用华为云API支持多records的特性，直接更新整个记录集
    """
    try:
        # 获取现有IP列表
        existing_ips = [record["value"] for record in existing_records]
        
        # 过滤黑名单IP（再次确保）
        filtered_ips, blocked_ips = filter_blacklist_ips(new_ips)
        
        if not filtered_ips:
            print(f"警告: 所有候选IP都在黑名单中，跳过更新")
            return
        
        # 限制新IP数量不超过affect_num，并选择性能最好的
        if len(filtered_ips) > affect_num:
            # 使用更严谨的排序选择最好的affect_num个IP
            filtered_ips = sorted(
                filtered_ips, 
                key=lambda x: get_sort_key(x, line_to_isp(line)),
                reverse=True
            )[:affect_num]
        
        new_ip_values = [ip_info["ip"] for ip_info in filtered_ips]
        
        # 如果没有现有记录，需要创建新记录
        if not existing_records:
            if new_ip_values:
                # 直接创建包含所有IP的记录集
                ret = cloud.create_record(domain, sub_domain, new_ip_values, record_type, line, ttl)
                if ret and (config["dns_server"] != 1 or ret.get("code") == 0):
                    print(f"CREATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                          f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                          f"----VALUES: {new_ip_values}")
                else:
                    print(f"CREATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                          f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                          f"----VALUES: {new_ip_values} ----MESSAGE: {ret.get('message', 'Unknown error')}")
            return
        
        # 有现有记录，使用第一条记录的ID进行更新（华为云一个线路只有一个记录集，包含多个IP）
        primary_record = existing_records[0]
        
        # 如果新旧IP列表完全相同，不需要更新
        if set(existing_ips) == set(new_ip_values):
            print(f"DNS RECORDS UNCHANGED: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                  f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                  f"----VALUES: {new_ip_values}")
            return
        
        # 执行批量更新
        ret = cloud.change_record(domain, primary_record["recordId"], sub_domain, new_ip_values, record_type, line, ttl)
        
        if ret and (config["dns_server"] != 1 or ret.get("code") == 0):
            print(f"BATCH UPDATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                  f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                  f"----OLD VALUES: {existing_ips} ----NEW VALUES: {new_ip_values}")
            
            # 如果有多余的现有记录（理论上不应该有，但以防万一）
            if len(existing_records) > 1:
                for extra_record in existing_records[1:]:
                    cloud.del_record(domain, extra_record["recordId"])
                    print(f"CLEANUP EXTRA RECORD: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                          f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                          f"----RECORDID: {extra_record['recordId']} ----VALUE: {extra_record['value']}")
        else:
            print(f"BATCH UPDATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                  f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                  f"----OLD VALUES: {existing_ips} ----NEW VALUES: {new_ip_values} "
                  f"----MESSAGE: {ret.get('message', 'Unknown error')}")
        
    except Exception as e:
        print(f"BATCH UPDATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
              f"----MESSAGE: {str(e)}")
        traceback.print_exc()

def line_to_isp(line_chinese):
    """
    将中文线路名称转换为ISP代码
    """
    line_map = {
        "移动": "CM",
        "联通": "CU", 
        "电信": "CT"
    }
    return line_map.get(line_chinese, None)

def changeDNS(line, s_info, c_info, domain, sub_domain, cloud):
    global config
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"

    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line_chinese = lines[line]
    
    # 过滤黑名单IP
    filtered_c_info, blocked_ips = filter_blacklist_ips(c_info)
    
    if not filtered_c_info:
        print(f"警告: 所有候选IP都在黑名单中，跳过更新 {sub_domain} - {line_chinese}")
        return
    
    # For Huawei Cloud DNS (dns_server == 3), use batch update with proper cleanup
    if config["dns_server"] == 3:
        # Extract IPs from filtered_c_info
        new_ips = [ip_info for ip_info in filtered_c_info]
        
        # 调用修复后的批量更新函数
        batch_update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                               s_info, new_ips, config["ttl"], config["affect_num"])
        return

    # Original logic for other DNS providers
    try:
        create_num = config["affect_num"] - len(s_info)
        if create_num == 0:
            for info in s_info:
                if len(filtered_c_info) == 0:
                    break
                # 选择IP时也考虑性能
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
                # 选择IP时也考虑性能
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
                # 选择IP时也考虑性能
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
    """
    清理指定子域名下目标线路的多余记录
    只删除指定线路的记录，不会影响其他线路
    """
    try:
        ret = cloud.get_record(domain, 100, sub_domain, record_type)
        if config["dns_server"] == 1 and ret["code"] != 0:
            return
        
        all_records = ret["data"]["records"]
        
        # 统计各线路记录
        line_records = {}
        for line in target_lines:
            line_records[line] = []
        
        for record in all_records:
            # 获取记录线路名称（根据不同DNS服务商适配）
            line_name = ""
            if config["dns_server"] == 1:  # 腾讯云
                line_name = record.get("line", "")
            elif config["dns_server"] == 2:  # 阿里云
                line_name = record.get("Line", "")
            elif config["dns_server"] == 3:  # 华为云
                line_name = record.get("line", "")
            
            # 只处理目标线路的记录
            if line_name in target_lines:
                line_records[line_name].append(record)
        
        print(f"子域名 {sub_domain} 下 {record_type} 记录统计:")
        for line, records in line_records.items():
            print(f"  {line}: {len(records)} 条")
            
    except Exception as e:
        print(f"检查记录时出错: {str(e)}")

def main(cloud):
    global config
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"
    
    # 定义只处理的三网线路
    three_net_lines = ["移动", "联通", "电信"]
    
    if len(DOMAINS) > 0:
        try:
            cfips = get_optimization_ip()
            if cfips == None or cfips["code"] != 200:
                print("GET CLOUDFLARE IP ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) )
                return
            cf_cmips = cfips["info"]["CM"]
            cf_cuips = cfips["info"]["CU"]
            cf_ctips = cfips["info"]["CT"]
            
            print(f"当前IP数量（已过滤黑名单） - 移动: {len(cf_cmips)}, 联通: {len(cf_cuips)}, 电信: {len(cf_ctips)}")
            
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    # 只处理三网线路（过滤掉AB和DEF）
                    filtered_lines = [line for line in lines if line in ["CM", "CU", "CT"]]
                    
                    if not filtered_lines:
                        print(f"子域名 {sub_domain} 没有指定三网线路，跳过")
                        continue
                    
                    # 检查记录状态，但只统计三网线路
                    cleanup_extra_records(cloud, domain, sub_domain, recordType, three_net_lines)
                    
                    temp_cf_cmips = cf_cmips.copy()
                    temp_cf_cuips = cf_cuips.copy()
                    temp_cf_ctips = cf_ctips.copy()
                    
                    # 获取当前A/AAAA记录
                    ret = cloud.get_record(domain, 100, sub_domain, recordType)
                    if config["dns_server"] != 1 or ret["code"] == 0:
                        if config["dns_server"] == 1 and "Free" in ret["data"]["domain"]["grade"] and config["affect_num"] > 2:
                            config["affect_num"] = 2
                        
                        # 只初始化三网线路的记录列表
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        
                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"] if config["dns_server"] != 2 else record["RecordId"]
                            info["value"] = record["value"]
                            
                            # 获取线路名称
                            line_name = ""
                            if config["dns_server"] == 1:  # 腾讯云
                                line_name = record["line"]
                            elif config["dns_server"] == 2:  # 阿里云
                                line_name = record["Line"]
                            elif config["dns_server"] == 3:  # 华为云
                                line_name = record["line"]
                            
                            # 只处理三网线路的记录
                            if line_name == "移动":
                                cm_info.append(info)
                            elif line_name == "联通":
                                cu_info.append(info)
                            elif line_name == "电信":
                                ct_info.append(info)
                            # 其他线路（境外、默认）不处理，保留原样
                        
                        print(f"当前三网记录数量 - 移动: {len(cm_info)}, 联通: {len(cu_info)}, 电信: {len(ct_info)}")
                        
                        # 只更新配置中指定的三网线路
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
    if config["dns_server"] == 1:
        cloud = QcloudApiv3(config["secretid"], config["secretkey"])
    elif config["dns_server"] == 2:
        cloud = AliApi(config["secretid"], config["secretkey"], config["region_ali"])
    elif config["dns_server"] == 3:
        cloud = HuaWeiApi(config["secretid"], config["secretkey"], config["region_hw"])
    if config["ipv4"] == "on":
        iptype = "v4"
        main(cloud)
    if config["ipv6"] == "on":
        iptype = "v6"
        main(cloud)
