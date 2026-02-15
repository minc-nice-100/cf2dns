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

# API地址列表
API_URLS = [
    "https://api.4ce.cn/api/bestCFIP",
    "https://vps789.com/public/sum/cfIpApi"
]

def get_optimization_ip():
    """
    从多个API获取IP信息并合并，平等对待所有返回的IP
    只处理CM、CU、CT线路
    """
    try:
        # 用于存储合并后的IP信息（去重后）
        merged_ips = {
            "v4": {"CM": [], "CU": [], "CT": []},
            "v6": {"CM": [], "CU": [], "CT": []}
        }
        
        headers = {'Content-Type': 'application/json'}
        
        # 遍历所有API
        for api_url in API_URLS:
            try:
                print(f"正在从 {api_url} 获取IP数据...")
                
                if "4ce.cn" in api_url:
                    # 第一个API的请求方式
                    response = requests.get(api_url, timeout=10)
                    if response.status_code == 200:
                        new_data = response.json()
                        if new_data and new_data.get("success") and "data" in new_data:
                            # 处理第一个API的数据
                            for ip_version in ["v4", "v6"]:
                                if ip_version in new_data["data"] and ip_version == iptype:
                                    for isp in ["CM", "CU", "CT"]:
                                        if isp in new_data["data"][ip_version]:
                                            for ip_info in new_data["data"][ip_version][isp]:
                                                # 转换数据格式
                                                converted_info = {
                                                    "ip": ip_info["ip"],
                                                    "name": ip_info.get("name", ""),
                                                    "colo": ip_info.get("colo", ""),
                                                    "latency": ip_info.get("latency", 0),
                                                    "speed": ip_info.get("speed", 0),
                                                    "uptime": ip_info.get("uptime", ""),
                                                    "source": api_url  # 标记来源
                                                }
                                                merged_ips[ip_version][isp].append(converted_info)
                            print(f"从 {api_url} 获取到数据")
                    else:
                        print(f"API {api_url} 请求失败，状态码: {response.status_code}")
                        
                elif "vps789.com" in api_url:
                    # 第二个API的请求方式
                    response = requests.get(api_url, timeout=10)
                    if response.status_code == 200:
                        new_data = response.json()
                        if new_data and new_data.get("code") == 0 and "data" in new_data:
                            # 处理第二个API的数据
                            # 第二个API返回的数据结构：data.CT, data.CU, data.CM, data.AllAvg
                            for isp in ["CM", "CU", "CT"]:
                                if isp in new_data["data"]:
                                    for ip_info in new_data["data"][isp]:
                                        # 转换数据格式
                                        converted_info = {
                                            "ip": ip_info["ip"],
                                            "ydLatencyAvg": ip_info.get("ydLatencyAvg", 0),
                                            "dxLatencyAvg": ip_info.get("dxLatencyAvg", 0),
                                            "ltLatencyAvg": ip_info.get("ltLatencyAvg", 0),
                                            "avgScore": ip_info.get("avgScore", 0),
                                            "createdTime": ip_info.get("createdTime", ""),
                                            "source": api_url  # 标记来源
                                        }
                                        merged_ips[iptype][isp].append(converted_info)
                            print(f"从 {api_url} 获取到数据")
                    else:
                        print(f"API {api_url} 请求失败，状态码: {response.status_code}")
                        
            except Exception as e:
                print(f"从 {api_url} 获取IP失败: {str(e)}")
                continue
        
        # 3. 从原API获取IP信息（通过provider_data配置）
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
                                ip_info["source"] = provider['get_ip_url']
                                merged_ips[iptype][isp].append(ip_info)
                    print(f"从原API获取到数据")
        except Exception as e:
            print(f"从原API获取IP失败: {str(e)}")
        
        # 4. 去重（基于IP地址）并平等对待所有IP
        for isp in ["CM", "CU", "CT"]:
            seen_ips = set()
            unique_ips = []
            for ip_info in merged_ips[iptype][isp]:
                ip = ip_info.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    # 统一化IP信息，确保所有IP有相同的字段结构
                    standardized_info = {
                        "ip": ip,
                        "source": ip_info.get("source", "unknown"),
                        "latency": ip_info.get("latency", ip_info.get("ydLatencyAvg", 0)),  # 统一使用latency字段
                        "score": ip_info.get("avgScore", ip_info.get("speed", 0)),  # 统一使用score字段
                        "createdTime": ip_info.get("createdTime", ip_info.get("uptime", ""))
                    }
                    unique_ips.append(standardized_info)
            
            # 随机打乱IP顺序，实现平等对待
            random.shuffle(unique_ips)
            merged_ips[iptype][isp] = unique_ips
        
        total_ips = sum(len(merged_ips[iptype][isp]) for isp in ["CM", "CU", "CT"])
        print(f"合并后总共获取到 {total_ips} 个{iptype} IP（已去重且随机排序）")
        
        # 5. 构建返回数据，保持与原API相同的格式
        result = {
            "code": 200,
            "info": {
                "CM": merged_ips[iptype]["CM"],
                "CU": merged_ips[iptype]["CU"],
                "CT": merged_ips[iptype]["CT"]
                # AB和DEF线路不处理
            }
        }
        
        return result
        
    except Exception as e:
        print(f"获取优化IP失败: {str(e)}")
        traceback.print_exc()
        return None

def batch_update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl):
    """
    Batch update DNS records for Huawei Cloud
    """
    try:
        # For Huawei Cloud, we need to handle batch operations differently
        # First, identify records to keep, update, and delete
        existing_ips = [record["value"] for record in existing_records]
        
        # IPs to add (in new_ips but not in existing_ips)
        ips_to_add = [ip for ip in new_ips if ip not in existing_ips]
        
        # IPs to remove (in existing_ips but not in new_ips)
        records_to_remove = [record for record in existing_records if record["value"] not in new_ips]
        
        # Delete records that are no longer needed
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
        
        # Create new records
        for ip in ips_to_add:
            ret = cloud.create_record(domain, sub_domain, ip, record_type, line, ttl)
            if config["dns_server"] != 1 or ret["code"] == 0:
                print(f"CREATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----VALUE: {ip}")
            else:
                print(f"CREATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----VALUE: {ip} ----MESSAGE: {ret.get('message', 'Unknown error')}")
        
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
    
    # For Huawei Cloud DNS (dns_server == 3), use batch update
    if config["dns_server"] == 3:
        # Extract IPs from c_info
        new_ips = [ip_info["ip"] for ip_info in c_info]
        
        # If we need to limit to affect_num
        if len(new_ips) > config["affect_num"]:
            new_ips = new_ips[:config["affect_num"]]
        
        # If we need to ensure exactly affect_num records (creating/deleting as needed)
        if len(s_info) != config["affect_num"] or set([r["value"] for r in s_info]) != set(new_ips):
            batch_update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                                   s_info, new_ips, config["ttl"])
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
                    temp_cf_cmips = cf_cmips.copy()
                    temp_cf_cuips = cf_cuips.copy()
                    temp_cf_ctips = cf_ctips.copy()
                    
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
                        
                        for record in ret["data"]["records"]:
                            # 只处理移动、联通、电信线路
                            if record["line"] == "移动":
                                info = {}
                                info["recordId"] = record["id"]
                                info["value"] = record["value"]
                                cm_info.append(info)
                            elif record["line"] == "联通":
                                info = {}
                                info["recordId"] = record["id"]
                                info["value"] = record["value"]
                                cu_info.append(info)
                            elif record["line"] == "电信":
                                info = {}
                                info["recordId"] = record["id"]
                                info["value"] = record["value"]
                                ct_info.append(info)
                        
                        for line in lines:
                            if line == "CM":
                                changeDNS("CM", cm_info, temp_cf_cmips, domain, sub_domain, cloud)
                            elif line == "CU":
                                changeDNS("CU", cu_info, temp_cf_cuips, domain, sub_domain, cloud)
                            elif line == "CT":
                                changeDNS("CT", ct_info, temp_cf_ctips, domain, sub_domain, cloud)
                            # AB和DEF线路不处理
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