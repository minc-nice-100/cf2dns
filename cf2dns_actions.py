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
        
        # 2. 从新API获取IP信息
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
                    print(f"从新API获取到 {sum(len(merged_ips[iptype][isp]) for isp in ['CM','CU','CT'])} 个IP")
            else:
                print(f"新API请求失败，状态码: {response.status_code}")
        except Exception as e:
            print(f"从新API获取IP失败: {str(e)}")
        
        # 3. 去重（基于IP地址）
        for isp in ["CM", "CU", "CT"]:
            seen_ips = set()
            unique_ips = []
            for ip_info in merged_ips[iptype][isp]:
                ip = ip_info.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip_info)
            merged_ips[iptype][isp] = unique_ips
        
        # 4. 按速度排序（如果有speed字段），速度高的优先
        for isp in ["CM", "CU", "CT"]:
            merged_ips[iptype][isp].sort(key=lambda x: x.get("speed", 0), reverse=True)
        
        total_ips = sum(len(merged_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
        print(f"合并后总共获取到 {total_ips} 个{iptype} IP")
        
        # 5. 构建返回数据，保持与原API相同的格式
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

def huawei_batch_update_records(cloud, domain, sub_domain, line_chinese, existing_records_v4, existing_records_v6, new_ips_v4, new_ips_v6, ttl):
    """
    华为云专用批量更新函数
    将同运营商的A记录和AAAA记录分别合并到同一个记录集中
    华为云支持一个记录集添加最多50个IP地址[citation:3]
    """
    try:
        # 处理A记录（IPv4）- 合并到同一个记录集
        if new_ips_v4:
            # 提取IP列表并限制数量
            new_ips_v4_list = [ip_info["ip"] for ip_info in new_ips_v4]
            if len(new_ips_v4_list) > config["affect_num"]:
                new_ips_v4_list = new_ips_v4_list[:config["affect_num"]]
            
            # 获取现有的A记录IP列表
            existing_ips_v4 = [r["value"] for r in existing_records_v4]
            
            # 检查是否需要更新（IP列表不同才更新）
            if set(existing_ips_v4) != set(new_ips_v4_list):
                # 如果有现有记录，先删除
                for record in existing_records_v4:
                    ret = cloud.del_record(domain, record["recordId"])
                    if ret["code"] == 0:
                        print(f"DELETE DNS SUCCESS (准备合并): ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                              f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese} "
                              f"----TYPE: A ----RECORDID: {record['recordId']} ----VALUE: {record['value']}")
                
                # 创建新的合并记录集（华为云支持一个记录集多个IP）
                # 注意：这里需要根据实际的HuaWeiApi实现调整
                # 如果create_record支持传入多个IP，直接调用；否则需要循环创建
                try:
                    # 尝试批量创建（如果API支持）
                    ret = cloud.create_record(domain, sub_domain, ",".join(new_ips_v4_list), "A", line_chinese, ttl)
                    if ret["code"] == 0:
                        print(f"CREATE DNS SUCCESS (合并记录集): ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                              f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese} "
                              f"----TYPE: A ----VALUES: {new_ips_v4_list}")
                    else:
                        # 如果批量失败，回退到逐条创建
                        print(f"批量创建失败，回退到逐条创建: {ret.get('message', '')}")
                        for ip in new_ips_v4_list:
                            ret = cloud.create_record(domain, sub_domain, ip, "A", line_chinese, ttl)
                            if ret["code"] == 0:
                                print(f"CREATE DNS SUCCESS (逐条): ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese} "
                                      f"----TYPE: A ----VALUE: {ip}")
                except Exception as e:
                    print(f"创建A记录失败: {str(e)}")
            else:
                print(f"A记录无需更新: {existing_ips_v4} == {new_ips_v4_list}")
        
        # 处理AAAA记录（IPv6）- 合并到同一个记录集
        if new_ips_v6:
            # 提取IP列表并限制数量
            new_ips_v6_list = [ip_info["ip"] for ip_info in new_ips_v6]
            if len(new_ips_v6_list) > config["affect_num"]:
                new_ips_v6_list = new_ips_v6_list[:config["affect_num"]]
            
            # 获取现有的AAAA记录IP列表
            existing_ips_v6 = [r["value"] for r in existing_records_v6]
            
            # 检查是否需要更新
            if set(existing_ips_v6) != set(new_ips_v6_list):
                # 删除现有记录
                for record in existing_records_v6:
                    ret = cloud.del_record(domain, record["recordId"])
                    if ret["code"] == 0:
                        print(f"DELETE DNS SUCCESS (准备合并): ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                              f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese} "
                              f"----TYPE: AAAA ----RECORDID: {record['recordId']} ----VALUE: {record['value']}")
                
                # 创建新的合并记录集
                try:
                    ret = cloud.create_record(domain, sub_domain, ",".join(new_ips_v6_list), "AAAA", line_chinese, ttl)
                    if ret["code"] == 0:
                        print(f"CREATE DNS SUCCESS (合并记录集): ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                              f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese} "
                              f"----TYPE: AAAA ----VALUES: {new_ips_v6_list}")
                    else:
                        print(f"批量创建失败，回退到逐条创建: {ret.get('message', '')}")
                        for ip in new_ips_v6_list:
                            ret = cloud.create_record(domain, sub_domain, ip, "AAAA", line_chinese, ttl)
                            if ret["code"] == 0:
                                print(f"CREATE DNS SUCCESS (逐条): ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese} "
                                      f"----TYPE: AAAA ----VALUE: {ip}")
                except Exception as e:
                    print(f"创建AAAA记录失败: {str(e)}")
            else:
                print(f"AAAA记录无需更新: {existing_ips_v6} == {new_ips_v6_list}")
                
    except Exception as e:
        print(f"HUAWEI BATCH UPDATE ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
              f"----MESSAGE: {str(e)}")
        traceback.print_exc()

def changeDNS(line, s_info, c_info, domain, sub_domain, cloud, record_type=None):
    """
    修改DNS记录
    如果传入了record_type，表示只处理特定类型的记录（用于分开处理A和AAAA）
    """
    global config
    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line_chinese = lines[line]
    
    # 华为云使用专用批量更新函数（在主流程中统一处理，这里不再调用）
    if config["dns_server"] == 3:
        # 华为云在main函数中统一处理，这里直接返回
        return
    
    # 非华为云的处理逻辑（保持不变）
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
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----TYPE: "+record_type+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip )
                else:
                    print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----TYPE: "+record_type+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
        elif create_num > 0:
            for i in range(create_num):
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.create_record(domain, sub_domain, cf_ip, record_type, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CREATE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----TYPE: "+record_type+"----VALUE: " + cf_ip )
                else:
                    print("CREATE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----TYPE: "+record_type+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
        else:
            for info in s_info:
                if create_num == 0 or len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info)-1))["ip"]
                if cf_ip in str(s_info):
                    create_num += 1
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, record_type, line_chinese, config["ttl"])
                if(config["dns_server"] != 1 or ret["code"] == 0):
                    print("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----TYPE: "+record_type+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip )
                else:
                    print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: "+line_chinese+"----TYPE: "+record_type+"----RECORDID: " + str(info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"] )
                create_num += 1
    except Exception as e:
        print("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(traceback.print_exc()))


def main(cloud):
    global config
    if len(DOMAINS) > 0:
        try:
            # 分别获取IPv4和IPv6的IP
            all_ips = {"v4": None, "v6": None}
            
            if config["ipv4"] == "on":
                global iptype
                iptype = "v4"
                all_ips["v4"] = get_optimization_ip()
            
            if config["ipv6"] == "on":
                iptype = "v6"
                all_ips["v6"] = get_optimization_ip()
            
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    # 存储每种线路的记录，按类型分开
                    records_by_line = {
                        "CM": {"A": [], "AAAA": []},
                        "CU": {"A": [], "AAAA": []},
                        "CT": {"A": [], "AAAA": []},
                        "AB": {"A": [], "AAAA": []},
                        "DEF": {"A": [], "AAAA": []}
                    }
                    
                    # 获取现有记录
                    for record_type in ["A", "AAAA"]:
                        ret = cloud.get_record(domain, 100, sub_domain, record_type)
                        if config["dns_server"] != 1 or ret["code"] == 0:
                            if config["dns_server"] == 1 and "Free" in ret["data"]["domain"]["grade"] and config["affect_num"] > 2:
                                config["affect_num"] = 2
                            
                            for record in ret["data"]["records"]:
                                info = {}
                                info["recordId"] = record["id"]
                                info["value"] = record["value"]
                                
                                # 根据线路分类
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
                        line_key = line  # CM, CU, CT, AB, DEF
                        
                        # 获取该线路的现有记录
                        existing_a = records_by_line[line_key]["A"]
                        existing_aaaa = records_by_line[line_key]["AAAA"]
                        
                        # 获取新IP（如果相应类型启用）
                        new_ips_v4 = []
                        new_ips_v6 = []
                        
                        if all_ips["v4"] and all_ips["v4"]["code"] == 200:
                            if line_key == "CM":
                                new_ips_v4 = all_ips["v4"]["info"]["CM"]
                            elif line_key == "CU":
                                new_ips_v4 = all_ips["v4"]["info"]["CU"]
                            elif line_key == "CT":
                                new_ips_v4 = all_ips["v4"]["info"]["CT"]
                            elif line_key in ["AB", "DEF"]:
                                new_ips_v4 = all_ips["v4"]["info"]["CT"]  # 境外和默认使用电信IP
                        
                        if all_ips["v6"] and all_ips["v6"]["code"] == 200:
                            if line_key == "CM":
                                new_ips_v6 = all_ips["v6"]["info"]["CM"]
                            elif line_key == "CU":
                                new_ips_v6 = all_ips["v6"]["info"]["CU"]
                            elif line_key == "CT":
                                new_ips_v6 = all_ips["v6"]["info"]["CT"]
                            elif line_key in ["AB", "DEF"]:
                                new_ips_v6 = all_ips["v6"]["info"]["CT"]  # 境外和默认使用电信IP
                        
                        # 华为云使用专用合并函数
                        if config["dns_server"] == 3:
                            line_chinese = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}[line]
                            huawei_batch_update_records(
                                cloud, domain, sub_domain, line_chinese,
                                existing_a, existing_aaaa,
                                new_ips_v4, new_ips_v6,
                                config["ttl"]
                            )
                        else:
                            # 非华为云，分别处理A和AAAA记录
                            if new_ips_v4:
                                changeDNS(line, existing_a, new_ips_v4.copy(), domain, sub_domain, cloud, "A")
                            if new_ips_v6:
                                changeDNS(line, existing_aaaa, new_ips_v6.copy(), domain, sub_domain, cloud, "AAAA")
                            
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
    
    # 主程序现在在main函数中分别处理v4和v6
    main(cloud)