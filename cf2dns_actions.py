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

def get_optimization_ip():
    try:
        headers = {'Content-Type': 'application/json'}
        data = {"key": config["key"], "type": iptype}
        provider = [item for item in provider_data if item['id'] == config["data_server"]][0]
        response = requests.post(provider['get_ip_url'], json=data, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            print("CHANGE OPTIMIZATION IP ERROR: REQUEST STATUS CODE IS NOT 200")
            return None
    except Exception as e:
        print("CHANGE OPTIMIZATION IP ERROR: " + str(e))
        return None

def batch_update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl):
    """
    使用华为云批量API更新DNS记录
    """
    try:
        # 构建完整的域名（FQDN格式）
        full_domain = f"{sub_domain}.{domain}." if sub_domain != "@" else f"{domain}."
        
        # 获取现有记录的ID列表
        existing_record_ids = [record["recordId"] for record in existing_records]
        existing_ips = [record["value"] for record in existing_records]
        
        # 确定需要删除的记录（存在于现有但不在新IP列表中）
        records_to_delete = []
        for record in existing_records:
            if record["value"] not in new_ips:
                records_to_delete.append(record["recordId"])
        
        # 确定需要创建的记录（存在于新IP但不在现有中）
        ips_to_create = [ip for ip in new_ips if ip not in existing_ips]
        
        # 步骤1: 如果有需要删除的记录，使用批量删除API
        if records_to_delete:
            ret = cloud.batch_delete_records(domain, records_to_delete)
            if config["dns_server"] != 1 or ret.get("code", 0) == 0:
                print(f"BATCH DELETE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----DELETED_COUNT: {len(records_to_delete)}")
            else:
                print(f"BATCH DELETE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----MESSAGE: {ret.get('message', 'Unknown error')}")
        
        # 步骤2: 如果有需要创建的记录，使用批量创建API
        if ips_to_create:
            # 对于华为云，批量创建记录集需要使用 CreateRecordSetWithBatchLines
            ret = cloud.batch_create_records(domain, full_domain, record_type, line, ips_to_create, ttl)
            if config["dns_server"] != 1 or ret.get("code", 0) == 0:
                print(f"BATCH CREATE DNS SUCCESS: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line} "
                      f"----CREATED_COUNT: {len(ips_to_create)} ----IPS: {', '.join(ips_to_create)}")
            else:
                print(f"BATCH CREATE DNS ERROR: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                      f"----MESSAGE: {ret.get('message', 'Unknown error')}")
        
        # 步骤3: 如果需要修改现有记录（华为云不支持直接修改，只能删除重建）
        # 但我们已经通过删除+创建的方式处理了所有变化
        
        # 如果没有任何变化，打印信息
        if not records_to_delete and not ips_to_create:
            print(f"NO DNS CHANGE NEEDED: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                  f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line}")
            
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
    
    # 对于华为云DNS，使用批量API
    if config["dns_server"] == 3:
        # 提取IP列表
        new_ips = [ip_info["ip"] for ip_info in c_info]
        
        # 限制记录数量不超过affect_num
        if len(new_ips) > config["affect_num"]:
            new_ips = new_ips[:config["affect_num"]]
        
        # 检查是否需要更新（数量不同或IP不同）
        current_ips = [record["value"] for record in s_info]
        if len(s_info) != config["affect_num"] or set(current_ips) != set(new_ips):
            batch_update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                                   s_info, new_ips, config["ttl"])
        else:
            print(f"DNS RECORDS ALREADY MATCH: ----Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} "
                  f"----DOMAIN: {domain} ----SUBDOMAIN: {sub_domain} ----RECORDLINE: {line_chinese}")
        return

    # 以下是原始逻辑，用于其他DNS提供商（腾讯云、阿里云）
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
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
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
                        
                        # 根据API返回格式提取记录信息
                        records_list = []
                        if config["dns_server"] == 3:  # 华为云
                            records_list = ret.get("recordsets", [])
                        else:  # 腾讯云、阿里云
                            records_list = ret["data"]["records"] if "data" in ret else ret.get("records", [])
                        
                        for record in records_list:
                            info = {}
                            info["recordId"] = record["id"]
                            info["value"] = record["records"][0] if isinstance(record.get("records"), list) and record["records"] else record.get("value", "")
                            
                            record_line = record.get("line", "")
                            if record_line == "移动":
                                cm_info.append(info)
                            elif record_line == "联通":
                                cu_info.append(info)
                            elif record_line == "电信":
                                ct_info.append(info)
                            elif record_line == "境外":
                                ab_info.append(info)
                            elif record_line == "默认":
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
