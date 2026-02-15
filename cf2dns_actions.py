#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, requests, time, base64, shutil, random, traceback

# 生成随机时间，范围在10到150之间
#random_time = random.uniform(10, 100)
#print("本次将等待{}秒执行".format(random_time))
# 延迟执行随机时间
#time.sleep(random_time)

from dns.qCloud import QcloudApiv3
from dns.aliyun import AliApi
from dns.huawei import HuaWeiApi

config = json.loads(os.environ["CONFIG"])
# CM:移动 CU:联通 CT:电信 AB:境外 DEF:默认
DOMAINS = json.loads(os.environ["DOMAINS"])
provider_data = json.loads(os.environ["PROVIDER"])

# 新的API地址
NEW_API_URL = "https://api.4ce.cn/api/bestCFIP"

def get_optimization_ip():
    """
    从两个API获取IP信息并合并
    原API：通过provider_data中的配置获取
    新API：https://api.4ce.cn/api/bestCFIP
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
                    for isp in ["CM", "CU", "CT"]:
                        if isp in old_data["info"]:
                            for ip_info in old_data["info"][isp]:
                                if isinstance(ip_info, str):
                                    ip_info = {"ip": ip_info}
                                elif isinstance(ip_info, dict) and "ip" not in ip_info:
                                    if "value" in ip_info:
                                        ip_info["ip"] = ip_info["value"]
                                merged_ips[iptype][isp].append(ip_info)
                    print(f"从原API获取到 {sum(len(merged_ips[iptype][isp]) for isp in ['CM','CU','CT'])} 个IP")
        except Exception as e:
            print(f"从原API获取IP失败: {str(e)}")
        
        # 2. 从新API获取IP信息
        try:
            response = requests.get(NEW_API_URL, timeout=10)
            if response.status_code == 200:
                new_data = response.json()
                if new_data and new_data.get("success") and "data" in new_data:
                    for ip_version in ["v4", "v6"]:
                        if ip_version in new_data["data"] and ip_version == iptype:
                            for isp in ["CM", "CU", "CT"]:
                                if isp in new_data["data"][ip_version]:
                                    for ip_info in new_data["data"][ip_version][isp]:
                                        converted_info = {
                                            "ip": ip_info["ip"],
                                            "name": ip_info.get("name", ""),
                                            "colo": ip_info.get("colo", ""),
                                            "latency": ip_info.get("latency", 0),
                                            "speed": ip_info.get("speed", 0),
                                            "uptime": ip_info.get("uptime", "")
                                        }
                                        merged_ips[ip_version][isp].append(converted_info)
                    print(f"从新API获取到 {sum(len(merged_ips[iptype][isp]) for isp in ['CM','CU','CT'])} 个IP")
        except Exception as e:
            print(f"从新API获取IP失败: {str(e)}")
        
        # 3. 去重
        for isp in ["CM", "CU", "CT"]:
            seen_ips = set()
            unique_ips = []
            for ip_info in merged_ips[iptype][isp]:
                ip = ip_info.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip_info)
            merged_ips[iptype][isp] = unique_ips
        
        # 4. 按速度排序
        for isp in ["CM", "CU", "CT"]:
            merged_ips[iptype][isp].sort(key=lambda x: x.get("speed", 0), reverse=True)
        
        total_ips = sum(len(merged_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
        print(f"合并后总共获取到 {total_ips} 个{iptype} IP")
        
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

def huawei_batch_update(cloud, domain, sub_domain, line_chinese, existing_records_v4, existing_records_v6, new_ips_v4, new_ips_v6, ttl):
    """
    华为云专用批量更新函数
    将同运营商的A和AAAA记录分别合并到同一个记录集中
    """
    try:
        # 处理A记录（IPv4）
        if new_ips_v4:
            # 提取IP列表并限制数量
            new_ips_v4_list = [ip_info["ip"] for ip_info in new_ips_v4]
            if len(new_ips_v4_list) > config["affect_num"]:
                new_ips_v4_list = new_ips_v4_list[:config["affect_num"]]
            
            # 获取现有的A记录IP列表
            existing_ips_v4 = [r["value"] for r in existing_records_v4]
            
            # 检查是否需要更新
            if set(existing_ips_v4) != set(new_ips_v4_list):
                print(f"准备更新A记录: 旧IP={existing_ips_v4}, 新IP={new_ips_v4_list}")
                
                # 删除所有现有A记录
                for record in existing_records_v4:
                    ret = cloud.del_record(domain, record["recordId"])
                    if ret.get("code") == 0:
                        print(f"删除旧A记录成功: {record['value']}")
                
                # 创建新的合并记录集（一次性传入所有IP）
                ret = cloud.create_record(domain, sub_domain, new_ips_v4_list, "A", line_chinese, ttl)
                if ret.get("code") == 0:
                    print(f"创建合并A记录集成功: {new_ips_v4_list}")
                else:
                    print(f"创建合并A记录集失败: {ret.get('message', '未知错误')}")
            else:
                print(f"A记录无需更新，IP列表相同")
        
        # 处理AAAA记录（IPv6）
        if new_ips_v6:
            new_ips_v6_list = [ip_info["ip"] for ip_info in new_ips_v6]
            if len(new_ips_v6_list) > config["affect_num"]:
                new_ips_v6_list = new_ips_v6_list[:config["affect_num"]]
            
            existing_ips_v6 = [r["value"] for r in existing_records_v6]
            
            if set(existing_ips_v6) != set(new_ips_v6_list):
                print(f"准备更新AAAA记录: 旧IP={existing_ips_v6}, 新IP={new_ips_v6_list}")
                
                for record in existing_records_v6:
                    ret = cloud.del_record(domain, record["recordId"])
                    if ret.get("code") == 0:
                        print(f"删除旧AAAA记录成功: {record['value']}")
                
                ret = cloud.create_record(domain, sub_domain, new_ips_v6_list, "AAAA", line_chinese, ttl)
                if ret.get("code") == 0:
                    print(f"创建合并AAAA记录集成功: {new_ips_v6_list}")
                else:
                    print(f"创建合并AAAA记录集失败: {ret.get('message', '未知错误')}")
            else:
                print(f"AAAA记录无需更新，IP列表相同")
                
    except Exception as e:
        print(f"华为云批量更新失败: {str(e)}")
        traceback.print_exc()

def changeDNS(line, s_info, c_info, domain, sub_domain, cloud, record_type=None):
    """
    修改DNS记录（非华为云使用）
    """
    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line_chinese = lines[line]
    
    try:
        create_num = config["affect_num"] - len(s_info)
        if create_num == 0:
            for info in s_info:
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, record_type, line_chinese, config["ttl"])
                if config["dns_server"] != 1 or ret["code"] == 0:
                    print(f"CHANGE DNS SUCCESS: {time.strftime('%Y-%m-%d %H:%M:%S')} DOMAIN:{domain} SUB:{sub_domain} LINE:{line_chinese} TYPE:{record_type} ID:{info['recordId']} IP:{cf_ip}")
        elif create_num > 0:
            for i in range(create_num):
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.create_record(domain, sub_domain, cf_ip, record_type, line_chinese, config["ttl"])
                if config["dns_server"] != 1 or ret["code"] == 0:
                    print(f"CREATE DNS SUCCESS: {time.strftime('%Y-%m-%d %H:%M:%S')} DOMAIN:{domain} SUB:{sub_domain} LINE:{line_chinese} TYPE:{record_type} IP:{cf_ip}")
        else:
            for info in s_info:
                if create_num == 0 or len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    create_num += 1
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, record_type, line_chinese, config["ttl"])
                if config["dns_server"] != 1 or ret["code"] == 0:
                    print(f"CHANGE DNS SUCCESS: {time.strftime('%Y-%m-%d %H:%M:%S')} DOMAIN:{domain} SUB:{sub_domain} LINE:{line_chinese} TYPE:{record_type} ID:{info['recordId']} IP:{cf_ip}")
                create_num += 1
    except Exception as e:
        print(f"CHANGE DNS ERROR: {str(e)}")
        traceback.print_exc()

def main(cloud):
    global config, iptype
    
    if len(DOMAINS) == 0:
        return
    
    # 分别获取IPv4和IPv6的IP
    all_ips = {"v4": None, "v6": None}
    
    if config["ipv4"] == "on":
        iptype = "v4"
        all_ips["v4"] = get_optimization_ip()
        if all_ips["v4"]:
            print(f"IPv4 IP数量 - 移动:{len(all_ips['v4']['info']['CM'])} 联通:{len(all_ips['v4']['info']['CU'])} 电信:{len(all_ips['v4']['info']['CT'])}")
    
    if config["ipv6"] == "on":
        iptype = "v6"
        all_ips["v6"] = get_optimization_ip()
        if all_ips["v6"]:
            print(f"IPv6 IP数量 - 移动:{len(all_ips['v6']['info']['CM'])} 联通:{len(all_ips['v6']['info']['CU'])} 电信:{len(all_ips['v6']['info']['CT'])}")
    
    for domain, sub_domains in DOMAINS.items():
        for sub_domain, lines in sub_domains.items():
            # 按线路和类型存储现有记录
            records_by_line = {
                "CM": {"A": [], "AAAA": []},
                "CU": {"A": [], "AAAA": []},
                "CT": {"A": [], "AAAA": []},
                "AB": {"A": [], "AAAA": []},
                "DEF": {"A": [], "AAAA": []}
            }
            
            # 获取现有A和AAAA记录
            for record_type in ["A", "AAAA"]:
                ret = cloud.get_record(domain, 100, sub_domain, record_type)
                if config["dns_server"] != 1 or ret.get("code") == 0:
                    if config["dns_server"] == 1 and "Free" in ret.get("data", {}).get("domain", {}).get("grade", "") and config["affect_num"] > 2:
                        config["affect_num"] = 2
                    
                    for record in ret.get("data", {}).get("records", []):
                        info = {"recordId": record["id"], "value": record["value"]}
                        if record["line"] == "移动":
                            records_by_line["CM"][record_type].append(info)
                        elif record["line"] == "联通":
                            records_by_line["CU"][record_type].append(info)
                        elif record["line"] == "电信":
                            records_by_line["CT"][record_type].append(info)
                        elif record["line"] == "境外":
                            records_by_line["AB"][record_type].append(info)
                        elif record["line"] == "默认":
                            records_by_line["DEF"][record_type].append(info)
            
            # 处理每个线路
            for line in lines:
                line_key = line
                line_chinese = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}[line]
                
                # 获取新IP
                new_ips_v4 = []
                new_ips_v6 = []
                
                if all_ips["v4"] and all_ips["v4"].get("code") == 200:
                    if line_key == "CM":
                        new_ips_v4 = all_ips["v4"]["info"]["CM"]
                    elif line_key == "CU":
                        new_ips_v4 = all_ips["v4"]["info"]["CU"]
                    elif line_key == "CT":
                        new_ips_v4 = all_ips["v4"]["info"]["CT"]
                    elif line_key in ["AB", "DEF"]:
                        new_ips_v4 = all_ips["v4"]["info"]["CT"]
                
                if all_ips["v6"] and all_ips["v6"].get("code") == 200:
                    if line_key == "CM":
                        new_ips_v6 = all_ips["v6"]["info"]["CM"]
                    elif line_key == "CU":
                        new_ips_v6 = all_ips["v6"]["info"]["CU"]
                    elif line_key == "CT":
                        new_ips_v6 = all_ips["v6"]["info"]["CT"]
                    elif line_key in ["AB", "DEF"]:
                        new_ips_v6 = all_ips["v6"]["info"]["CT"]
                
                # 华为云使用合并更新
                if config["dns_server"] == 3:
                    huawei_batch_update(
                        cloud, domain, sub_domain, line_chinese,
                        records_by_line[line_key]["A"],
                        records_by_line[line_key]["AAAA"],
                        new_ips_v4, new_ips_v6,
                        config["ttl"]
                    )
                else:
                    # 非华为云，分别处理
                    if new_ips_v4:
                        changeDNS(line, records_by_line[line_key]["A"], new_ips_v4.copy(), 
                                 domain, sub_domain, cloud, "A")
                    if new_ips_v6:
                        changeDNS(line, records_by_line[line_key]["AAAA"], new_ips_v6.copy(), 
                                 domain, sub_domain, cloud, "AAAA")

if __name__ == '__main__':
    # 初始化DNS客户端
    if config["dns_server"] == 1:
        cloud = QcloudApiv3(config["secretid"], config["secretkey"])
    elif config["dns_server"] == 2:
        cloud = AliApi(config["secretid"], config["secretkey"], config.get("region_ali", "cn-hangzhou"))
    elif config["dns_server"] == 3:
        cloud = HuaWeiApi(config["secretid"], config["secretkey"], config.get("region_hw", "cn-east-3"))
    else:
        print("不支持的DNS服务商")
        sys.exit(1)
    
    # 执行主程序
    main(cloud)