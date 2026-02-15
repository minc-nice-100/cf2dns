#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys
import os
import json
import requests
import time
import random
import traceback
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2 import *
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion

# 读取环境变量
config = json.loads(os.environ["CONFIG"])
DOMAINS = json.loads(os.environ["DOMAINS"])
provider_data = json.loads(os.environ["PROVIDER"])

# 新的API地址
NEW_API_URL = "https://api.4ce.cn/api/bestCFIP"


class HuaWeiApi:
    """华为云DNS API封装（V3版本）"""
    
    def __init__(self, ACCESSID, SECRETKEY, REGION='cn-east-3'):
        self.AK = ACCESSID
        self.SK = SECRETKEY
        self.region = REGION
        
        credentials = BasicCredentials(self.AK, self.SK)
        
        self.client = DnsClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(DnsRegion.value_of(self.region)) \
            .build()
        
        self.zone_id = self.get_zones()

    def del_record(self, domain, record_id):
        """删除单条记录集"""
        try:
            request = DeleteRecordSetsRequest()
            request.zone_id = self.zone_id.get(domain + '.')
            if not request.zone_id:
                return {"code": 404, "message": f"域名{domain}不存在"}
            
            request.recordset_id = record_id
            response = self.client.delete_record_sets(request)
            return json.loads(str(response))
        except Exception as e:
            return {"code": 500, "message": str(e)}

    def get_record(self, domain, length, sub_domain, record_type):
        """获取记录集列表"""
        try:
            request = ListRecordSetsWithLineRequest()
            request.limit = length
            request.type = record_type
            
            if sub_domain == '@':
                request.name = domain + "."
            else:
                request.name = sub_domain + '.' + domain + "."
            
            response = self.client.list_record_sets_with_line(request)
            data = json.loads(str(response))
            
            result = {'data': {'records': []}, 'code': 0}
            
            for record in data.get('recordsets', []):
                record_name = record.get('name', '')
                expected_name = (domain + '.') if sub_domain == '@' else (sub_domain + '.' + domain + '.')
                
                if record_name == expected_name and record.get('type') == record_type:
                    # 转换线路格式
                    record['line'] = self.line_format(record.get('line', 'default_view'))
                    
                    # 为每个IP创建一条记录
                    records_list = record.get('records', [])
                    for ip in records_list:
                        record_item = {
                            'id': record.get('id'),
                            'line': record['line'],
                            'value': ip,
                            'type': record.get('type'),
                            'ttl': record.get('ttl'),
                            'name': record.get('name')
                        }
                        result['data']['records'].append(record_item)
            
            return result
        except Exception as e:
            return {"code": 500, "data": {"records": []}, "message": str(e)}

    def create_record(self, domain, sub_domain, values, record_type, line, ttl):
        """创建记录集（支持批量IP）"""
        try:
            request = CreateRecordSetWithLineRequest()
            request.zone_id = self.zone_id.get(domain + '.')
            if not request.zone_id:
                return {"code": 404, "message": f"域名{domain}不存在"}
            
            if sub_domain == '@':
                name = domain + "."
            else:
                name = sub_domain + '.' + domain + "."
            
            # 确保values是列表
            if isinstance(values, str):
                records_list = [values]
            else:
                records_list = values
            
            request.body = CreateRecordSetWithLineReq(
                type=record_type,
                name=name,
                ttl=ttl,
                records=records_list,
                line=self.line_format(line)
            )
            
            response = self.client.create_record_set_with_line(request)
            return json.loads(str(response))
        except Exception as e:
            return {"code": 500, "message": str(e)}

    def get_zones(self):
        """获取所有公网域名的zone_id映射"""
        try:
            request = ListPublicZonesRequest()
            response = self.client.list_public_zones(request)
            result = json.loads(str(response))
            
            zone_id = {}
            for zone in result.get('zones', []):
                zone_id[zone['name']] = zone['id']
            return zone_id
        except Exception as e:
            print(f"获取域名列表失败: {e}")
            return {}

    def line_format(self, line):
        """线路格式转换"""
        lines = {
            '默认': 'default_view',
            '电信': 'Dianxin',
            '联通': 'Liantong',
            '移动': 'Yidong',
            '境外': 'Abroad',
            'default_view': '默认',
            'Dianxin': '电信',
            'Liantong': '联通',
            'Yidong': '移动',
            'Abroad': '境外',
        }
        return lines.get(line, line)


def get_optimization_ip(iptype):
    """从两个API获取IP信息并合并"""
    try:
        merged_ips = {"CM": [], "CU": [], "CT": []}
        headers = {'Content-Type': 'application/json'}
        
        # 1. 从原API获取IP信息
        try:
            data = {"key": config["key"], "type": iptype}
            provider = [p for p in provider_data if p['id'] == config["data_server"]][0]
            response = requests.post(provider['get_ip_url'], json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                old_data = response.json()
                if old_data and old_data.get("code") == 200:
                    for isp in ["CM", "CU", "CT"]:
                        for ip_info in old_data["info"].get(isp, []):
                            if isinstance(ip_info, str):
                                ip_info = {"ip": ip_info}
                            elif isinstance(ip_info, dict) and "ip" not in ip_info:
                                if "value" in ip_info:
                                    ip_info["ip"] = ip_info["value"]
                            merged_ips[isp].append(ip_info)
                    print(f"从原API获取到 {sum(len(merged_ips[isp]) for isp in ['CM','CU','CT'])} 个{iptype} IP")
        except Exception as e:
            print(f"从原API获取IP失败: {e}")
        
        # 2. 从新API获取IP信息
        try:
            response = requests.get(NEW_API_URL, timeout=10)
            if response.status_code == 200:
                new_data = response.json()
                if new_data and new_data.get("success") and "data" in new_data:
                    ip_version = iptype
                    if ip_version in new_data["data"]:
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
                                    merged_ips[isp].append(converted_info)
                    print(f"从新API获取到 {sum(len(merged_ips[isp]) for isp in ['CM','CU','CT'])} 个{iptype} IP")
        except Exception as e:
            print(f"从新API获取IP失败: {e}")
        
        # 3. 去重
        for isp in ["CM", "CU", "CT"]:
            seen_ips = set()
            unique_ips = []
            for ip_info in merged_ips[isp]:
                ip = ip_info.get("ip", "")
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip_info)
            merged_ips[isp] = unique_ips
        
        # 4. 按速度排序
        for isp in ["CM", "CU", "CT"]:
            merged_ips[isp].sort(key=lambda x: x.get("speed", 0), reverse=True)
        
        total_ips = sum(len(merged_ips[isp]) for isp in ["CM", "CU", "CT"])
        print(f"合并后总共获取到 {total_ips} 个{iptype} IP")
        
        return {
            "code": 200,
            "info": merged_ips
        }
        
    except Exception as e:
        print(f"获取优化IP失败: {e}")
        traceback.print_exc()
        return None


def update_carrier_records(cloud, domain, sub_domain, lines, all_ips, ttl):
    """更新移动、联通、电信的A和AAAA记录（删除旧记录 + 添加新记录）"""
    try:
        # 要处理的线路映射
        line_mapping = {
            "CM": "移动",
            "CU": "联通", 
            "CT": "电信"
        }
        
        # 要处理的记录类型
        record_types = ["A", "AAAA"]
        
        print(f"\n开始更新 {domain} - {sub_domain} 的运营商记录...")
        
        # 首先获取所有现有记录
        existing_records = {"A": {}, "AAAA": {}}
        
        for record_type in record_types:
            ret = cloud.get_record(domain, 100, sub_domain, record_type)
            if ret.get("code") == 0:
                for record in ret.get("data", {}).get("records", []):
                    line = record["line"]
                    if line in ["移动", "联通", "电信"]:
                        record_id = record["id"]
                        if record_id not in existing_records[record_type]:
                            existing_records[record_type][record_id] = {
                                "line": line,
                                "ips": []
                            }
                        existing_records[record_type][record_id]["ips"].append(record["value"])
        
        # 删除所有现有的运营商记录
        deleted_count = 0
        for record_type in record_types:
            for record_id, record_info in existing_records[record_type].items():
                ret = cloud.del_record(domain, record_id)
                if ret.get("code") == 0 or "code" not in ret:
                    print(f"✓ 删除旧{record_type}记录: {record_info['line']} - {record_info['ips']}")
                    deleted_count += 1
                else:
                    print(f"✗ 删除失败: {record_info['line']} - {ret.get('message', '未知错误')}")
        
        if deleted_count > 0:
            print(f"已删除 {deleted_count} 条旧记录")
        
        # 添加新记录
        created_count = 0
        
        # 处理配置中指定的线路
        for line in lines:
            if line not in line_mapping:
                continue  # 跳过非运营商线路
                
            line_chinese = line_mapping[line]
            
            # 获取新IP
            new_ips_v4 = []
            new_ips_v6 = []
            
            if all_ips.get("v4") and all_ips["v4"].get("code") == 200:
                if line == "CM":
                    new_ips_v4 = all_ips["v4"]["info"]["CM"]
                elif line == "CU":
                    new_ips_v4 = all_ips["v4"]["info"]["CU"]
                elif line == "CT":
                    new_ips_v4 = all_ips["v4"]["info"]["CT"]
            
            if all_ips.get("v6") and all_ips["v6"].get("code") == 200:
                if line == "CM":
                    new_ips_v6 = all_ips["v6"]["info"]["CM"]
                elif line == "CU":
                    new_ips_v6 = all_ips["v6"]["info"]["CU"]
                elif line == "CT":
                    new_ips_v6 = all_ips["v6"]["info"]["CT"]
            
            # 添加A记录（IPv4）
            if new_ips_v4:
                ip_list = [ip["ip"] for ip in new_ips_v4]
                if len(ip_list) > config["affect_num"]:
                    ip_list = ip_list[:config["affect_num"]]
                
                ret = cloud.create_record(domain, sub_domain, ip_list, "A", line_chinese, ttl)
                if ret.get("code") == 0 or "code" not in ret:
                    print(f"✓ 创建新A记录: {line_chinese} - {ip_list}")
                    created_count += 1
                else:
                    print(f"✗ 创建A记录失败: {line_chinese} - {ret.get('message', '未知错误')}")
            
            # 添加AAAA记录（IPv6）
            if new_ips_v6:
                ip_list = [ip["ip"] for ip in new_ips_v6]
                if len(ip_list) > config["affect_num"]:
                    ip_list = ip_list[:config["affect_num"]]
                
                ret = cloud.create_record(domain, sub_domain, ip_list, "AAAA", line_chinese, ttl)
                if ret.get("code") == 0 or "code" not in ret:
                    print(f"✓ 创建新AAAA记录: {line_chinese} - {ip_list}")
                    created_count += 1
                else:
                    print(f"✗ 创建AAAA记录失败: {line_chinese} - {ret.get('message', '未知错误')}")
        
        if created_count > 0:
            print(f"已创建 {created_count} 条新记录")
        
        print(f"完成 {domain} - {sub_domain} 的运营商记录更新\n")
        
    except Exception as e:
        print(f"更新记录时出错: {e}")
        traceback.print_exc()


def main():
    """主函数"""
    if len(DOMAINS) == 0:
        print("没有配置域名")
        return
    
    # 初始化华为云客户端
    cloud = HuaWeiApi(
        config["secretid"],
        config["secretkey"],
        config.get("region_hw", "cn-east-3")
    )
    
    print("=" * 60)
    print("开始更新移动、联通、电信的A和AAAA记录")
    print("（删除旧记录 + 添加新记录）")
    print("其他线路（境外、默认）保持不变")
    print("=" * 60)
    
    # 分别获取IPv4和IPv6的IP
    all_ips = {"v4": None, "v6": None}
    
    if config.get("ipv4") == "on":
        all_ips["v4"] = get_optimization_ip("v4")
        if all_ips["v4"]:
            print(f"\nIPv4 IP数量 - 移动:{len(all_ips['v4']['info']['CM'])} 联通:{len(all_ips['v4']['info']['CU'])} 电信:{len(all_ips['v4']['info']['CT'])}")
    
    if config.get("ipv6") == "on":
        all_ips["v6"] = get_optimization_ip("v6")
        if all_ips["v6"]:
            print(f"IPv6 IP数量 - 移动:{len(all_ips['v6']['info']['CM'])} 联通:{len(all_ips['v6']['info']['CU'])} 电信:{len(all_ips['v6']['info']['CT'])}")
    
    # 遍历所有域名和子域名
    for domain, sub_domains in DOMAINS.items():
        for sub_domain, lines in sub_domains.items():
            # 检查是否有运营商线路
            has_carrier = any(line in ["CM", "CU", "CT"] for line in lines)
            if has_carrier:
                update_carrier_records(cloud, domain, sub_domain, lines, all_ips, config["ttl"])
            else:
                print(f"跳过 {domain} - {sub_domain}（没有配置运营商线路）")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"程序执行失败: {e}")
        traceback.print_exc()
        sys.exit(1)