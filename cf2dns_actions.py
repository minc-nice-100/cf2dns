#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, requests, time, base64, shutil, random, traceback

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

def get_optimization_ip():
    """
    从多个API获取IP信息并合并
    原API：通过provider_data中的配置获取
    新API：https://api.4ce.cn/api/bestCFIP
    VPS789 API：https://vps789.com/public/sum/cfIpApi
    """
    try:
        # 用于存储合并后的IP信息
        merged_ips = {
            "v4": {"CM": [], "CU": [], "CT": []},
            "v6": {"CM": [], "CU": [], "CT": []}
        }
        
        headers = {'Content-Type': 'application/json'}
        
        # 1. 从原API获取IP信息
        try:
            data = {"key": config["key"], "type": iptype}
            provider = [item for item in provider_data if item['id'] == config["data_server"]][0]
            response = requests.post(provider['get_ip_url'], json=data, headers=headers, timeout=10)
            if response.status_code == 200:
                old_data = response.json()
                if old_data and old_data.get("code") == 200:
                    # 合并原API的IP信息
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
                                merged_ips[iptype][isp].append(ip_info)
                    print(f"从原API获取到 {sum(len(merged_ips[iptype][isp]) for isp in ['CM','CU','CT'])} 个IP")
            else:
                print(f"原API请求失败，状态码: {response.status_code}")
        except Exception as e:
            print(f"从原API获取IP失败: {str(e)}")
        
        # 2. 从新API (4ce.cn) 获取IP信息
        try:
            response = requests.get(NEW_API_URL, timeout=10)
            if response.status_code == 200:
                new_data = response.json()
                if new_data and new_data.get("success") and "data" in new_data:
                    # 合并新API的IP信息
                    for ip_version in ["v4", "v6"]:
                        if ip_version in new_data["data"] and ip_version == iptype:
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
                                        merged_ips[ip_version][isp].append(converted_info)
                    print(f"从4ce.cn API获取到 {sum(len(merged_ips[iptype][isp]) for isp in ['CM','CU','CT'])} 个IP")
            else:
                print(f"4ce.cn API请求失败，状态码: {response.status_code}")
        except Exception as e:
            print(f"从4ce.cn API获取IP失败: {str(e)}")
        
        # 3. 从VPS789 API获取IP信息
        try:
            response = requests.get(VPS789_API_URL, timeout=10)
            if response.status_code == 200:
                vps789_data = response.json()
                if vps789_data and vps789_data.get("code") == 0 and "data" in vps789_data:
                    # 处理VPS789 API的数据
                    for isp in ["CM", "CU", "CT"]:
                        if isp in vps789_data["data"]:
                            for ip_info in vps789_data["data"][isp]:
                                # 转换VPS789的数据格式
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
                                merged_ips[iptype][isp].append(converted_info)
                    
                    # 如果有AllAvg数据，可以将其分配到各个运营商或作为备用
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
                            # 将AllAvg的IP添加到所有运营商
                            for isp in ["CM", "CU", "CT"]:
                                merged_ips[iptype][isp].append(converted_info)
                    
                    print(f"从VPS789 API获取到 {sum(len(merged_ips[iptype][isp]) for isp in ['CM','CU','CT'])} 个IP")
            else:
                print(f"VPS789 API请求失败，状态码: {response.status_code}")
        except Exception as e:
            print(f"从VPS789 API获取IP失败: {str(e)}")
        
        # 4. 去重（基于IP地址）
        for isp in ["CM", "CU", "CT"]:
            seen_ips = set()
            unique_ips = []
            for ip_info in merged_ips[iptype][isp]:
                ip = ip_info.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip_info)
            merged_ips[iptype][isp] = unique_ips
        
        # 5. 按速度或分数排序（优先使用speed，如果没有则使用avgScore）
        for isp in ["CM", "CU", "CT"]:
            merged_ips[iptype][isp].sort(key=lambda x: (
                x.get("speed", 0) or  # 如果有speed字段
                x.get("avgScore", 0) or  # 如果有avgScore字段
                0
            ), reverse=True)
        
        total_ips = sum(len(merged_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
        print(f"合并后总共获取到 {total_ips} 个{iptype} IP")
        
        # 6. 构建返回数据，保持与原API相同的格式
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
    Batch update DNS records for Huawei Cloud with proper cleanup
    """
    try:
        # 获取现有IP列表
        existing_ips = [record["value"] for record in existing_records]
        
        # 限制新IP数量不超过affect_num
        if len(new_ips) > affect_num:
            new_ips = new_ips[:affect_num]
        
        # 确保新IP列表长度正好为affect_num（如果可用IP不足，用None占位）
        while len(new_ips) < affect_num:
            new_ips.append(None)  # None表示这个位置不需要记录
        
        print(f"华为云批量更新 - 域名: {domain}.{sub_domain}, 线路: {line}, 目标数量: {affect_num}")
        print(f"现有IP: {existing_ips}")
        print(f"目标IP: {[ip for ip in new_ips if ip]}")
        
        # 确定需要删除和保留的记录
        records_to_remove = []
        records_to_keep = []
        
        # 按顺序处理现有记录
        for i, record in enumerate(existing_records):
            # 如果超出数量限制，或者IP不在目标列表中（且目标位置不是None），则删除
            if i >= affect_num:
                records_to_remove.append(record)
                print(f"记录 {i+1} (IP: {record['value']}) - 超出数量限制，标记删除")
            elif i < len(new_ips) and new_ips[i] and record["value"] == new_ips[i]:
                # IP匹配且位置正确，保留
                records_to_keep.append(record)
                print(f"记录 {i+1} (IP: {record['value']}) - IP匹配，保留")
            else:
                # IP不匹配，需要删除（后续会在对应位置创建新记录）
                records_to_remove.append(record)
                print(f"记录 {i+1} (IP: {record['value']}) - IP不匹配，标记删除")
        
        # 确定需要添加的IP（新列表中且不在保留记录中）
        kept_ips = [r["value"] for r in records_to_keep]
        ips_to_add = []
        
        for i, ip in enumerate(new_ips):
            if ip and ip not in kept_ips:
                ips_to_add.append((i, ip))  # 记录位置和IP
                print(f"需要添加IP: {ip} 到位置 {i+1}")
        
        # 删除不需要的记录
        for record in records_to_remove:
            ret = cloud.del_record(domain, record["recordId"])
            if config["dns_server"] != 1 or ret["code"] == 0:
                print(f"DELETE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----RECORDID: {record['recordId']} ----VALUE: {record['value']}")
            else:
                print(f"DELETE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----RECORDID: {record['recordId']} ----VALUE: {record['value']} "
                      f"----MESSAGE: {ret.get('message', 'Unknown error')}")
        
        # 创建新记录（按位置顺序）
        for position, ip in ips_to_add:
            ret = cloud.create_record(domain, sub_domain, ip, record_type, line, ttl)
            if config["dns_server"] != 1 or ret["code"] == 0:
                print(f"CREATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----VALUE: {ip} ----POSITION: {position+1}")
            else:
                print(f"CREATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----VALUE: {ip} ----MESSAGE: {ret.get('message', 'Unknown error')}")
        
        # 统计最终结果
        final_kept = len(records_to_keep)
        final_added = len(ips_to_add)
        final_removed = len(records_to_remove)
        print(f"华为云批量更新完成 - 保留: {final_kept}, 新增: {final_added}, 删除: {final_removed}")
        
    except Exception as e:
        print(f"BATCH UPDATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
              f"----MESSAGE: {str(e)}")
        traceback.print_exc()

def changeDNS(line, s_info, c_info, domain, sub_domain, cloud):
    global config
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"

    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line_chinese = lines[line]
    
    # For Huawei Cloud DNS (dns_server == 3), use batch update with proper cleanup
    if config["dns_server"] == 3:
        # Extract IPs from c_info
        new_ips = [ip_info["ip"] for ip_info in c_info]
        
        # 调用修复后的批量更新函数
        batch_update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                               s_info, new_ips, config["ttl"], config["affect_num"])
        return

    # Original logic for other DNS providers
    try:
        create_num = config["affect_num"] - len(s_info)
        if create_num == 0:
            for info in s_info:
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, recordType, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip )
                else:
                    print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
        elif create_num > 0:
            for i in range(create_num):
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.create_record(domain, sub_domain, cf_ip, recordType, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CREATE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----VALUE: " + cf_ip )
                else:
                    print("CREATE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
        else:
            for info in s_info:
                if create_num == 0 or len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
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

def cleanup_extra_records(cloud, domain, sub_domain, record_type, valid_lines):
    """
    清理不属于指定线路的多余记录
    """
    try:
        ret = cloud.get_record(domain, 100, sub_domain, record_type)
        if config["dns_server"] == 1 and ret["code"] != 0:
            return
        
        all_records = ret["data"]["records"]
        cleaned_count = 0
        
        for record in all_records:
            if record["type"] == record_type and record["line"] not in valid_lines:
                # 删除不在指定线路中的记录
                if config["dns_server"] == 3:  # 华为云
                    del_ret = cloud.del_record(domain, record["id"])
                    if del_ret.get("code") == 0:
                        print(f"清理多余记录: {record['value']} (线路: {record['line']})")
                        cleaned_count += 1
                elif config["dns_server"] == 1:  # 腾讯云
                    del_ret = cloud.del_record(domain, record["id"])
                    if del_ret["code"] == 0:
                        print(f"清理多余记录: {record['value']} (线路: {record['line']})")
                        cleaned_count += 1
                elif config["dns_server"] == 2:  # 阿里云
                    del_ret = cloud.del_record(domain, record["RecordId"])
                    if del_ret.get("code") == 0:
                        print(f"清理多余记录: {record['value']} (线路: {record['line']})")
                        cleaned_count += 1
        
        if cleaned_count > 0:
            print(f"总共清理了 {cleaned_count} 条多余记录")
            
    except Exception as e:
        print(f"清理多余记录时出错: {str(e)}")

def main(cloud):
    global config
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"
    
    if len(DOMAINS) > 0:
        try:
            cfips = get_optimization_ip()
            if cfips == None or cfips["code"] != 200:
                print("GET CLOUDFLARE IP ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) )
                return
            cf_cmips = cfips["info"]["CM"]
            cf_cuips = cfips["info"]["CU"]
            cf_ctips = cfips["info"]["CT"]
            
            print(f"当前IP数量 - 移动: {len(cf_cmips)}, 联通: {len(cf_cuips)}, 电信: {len(cf_ctips)}")
            
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    # 定义有效的线路列表
                    valid_lines = ["移动", "联通", "电信", "境外", "默认"]
                    
                    # 清理不属于指定线路的多余记录
                    cleanup_extra_records(cloud, domain, sub_domain, recordType, valid_lines)
                    
                    temp_cf_cmips = cf_cmips.copy()
                    temp_cf_cuips = cf_cuips.copy()
                    temp_cf_ctips = cf_ctips.copy()
                    temp_cf_abips = cf_ctips.copy()
                    temp_cf_defips = cf_ctips.copy()
                    
                    if config["dns_server"] == 1:
                        ret = cloud.get_record(domain, 20, sub_domain, "CNAME")
                        if ret["code"] == 0:
                            for record in ret["data"]["records"]:
                                if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                    retMsg = cloud.del_record(domain, record["id"])
                                    if(retMsg["code"] == 0):
                                        print("DELETE DNS SUCCESS: ----Time: "  + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+record["line"] )
                                    else:
                                        print("DELETE DNS ERROR: ----Time: "  + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+record["line"] + "----MESSAGE: " + retMsg["message"] )
                    
                    ret = cloud.get_record(domain, 100, sub_domain, recordType)
                    if config["dns_server"] != 1 or ret["code"] == 0:
                        if config["dns_server"] == 1 and "Free" in ret["data"]["domain"]["grade"] and config["affect_num"] > 2:
                            config["affect_num"] = 2
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        ab_info = []
                        def_info = []
                        
                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"] if config["dns_server"] != 2 else record["RecordId"]
                            info["value"] = record["value"]
                            line_name = record["line"] if config["dns_server"] != 2 else record["Line"]
                            
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
                        
                        for line in lines:
                            if line == "CM":
                                changeDNS("CM", cm_info, temp_cf_cmips, domain, sub_domain, cloud)
                            elif line == "CU":
                                changeDNS("CU", cu_info, temp_cf_cuips, domain, sub_domain, cloud)
                            elif line == "CT":
                                changeDNS("CT", ct_info, temp_cf_ctips, domain, sub_domain, cloud)
                            elif line == "AB":
                                changeDNS("AB", ab_info, temp_cf_abips, domain, sub_domain, cloud)
                            elif line == "DEF":
                                changeDNS("DEF", def_info, temp_cf_defips, domain, sub_domain, cloud)
                        
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