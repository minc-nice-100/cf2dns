#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com
# 纯HTTP请求实现华为云DNS记录更新（适配cn-north-4区域 + official.platform.cname.itedev.com）

import sys
import os
import json
import time
import hmac
import hashlib
import base64
import requests
import traceback
from datetime import datetime

# 读取环境变量（添加异常处理）
try:
    config = json.loads(os.environ.get("CONFIG", "{}"))
    DOMAINS = json.loads(os.environ.get("DOMAINS", "{}"))
    provider_data = json.loads(os.environ.get("PROVIDER", "[]"))
except json.JSONDecodeError as e:
    print(f"环境变量解析失败: {e}")
    sys.exit(1)

# 新的API地址
NEW_API_URL = "https://api.4ce.cn/api/bestCFIP"

# 配置默认值（适配cn-north-4区域）
DEFAULT_CONFIG = {
    "key": "",
    "data_server": "",
    "secretid": "",  # 华为云AK
    "secretkey": "", # 华为云SK
    "region_hw": "cn-north-4",  # 适配你的区域
    "ipv4": "on",
    "ipv6": "off",
    "affect_num": 5,
    "ttl": 600
}
# 合并配置，使用默认值填充缺失项
config = {**DEFAULT_CONFIG, **config}

# 华为云DNS API基础配置（适配cn-north-4区域）
DNS_API_BASE = "https://dns.{}.myhuaweicloud.com/v2".format(config["region_hw"])
# 线路映射（华为云DNS API使用的线路编码）
LINE_MAPPING = {
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


class HuaweiDNSAPI:
    """华为云DNS API封装（纯HTTP请求版，适配cn-north-4区域）"""
    
    def __init__(self, ak, sk, region):
        self.ak = ak
        self.sk = sk
        self.region = region
        self.base_url = DNS_API_BASE
        self.zone_ids = self._get_all_zone_ids()  # 缓存域名zone_id映射
        # 手动补充控制台zone_id（防止API获取失败）
        self.manual_zone_ids = {
            "official.platform.cname.itedev.com.": "ff8080829a978db4019b3af3e7093a8c"
        }
        # 合并手动配置和API获取的zone_id
        self.zone_ids = {**self.zone_ids, **self.manual_zone_ids}
    
    def _sign_request(self, method, path, params=None, body=None):
        """
        生成华为云API请求签名（参考官方文档：https://support.huaweicloud.com/devg-apisign/api-sign-provide.html）
        适配cn-north-4区域签名规则
        """
        # 1. 构造请求时间
        now = datetime.utcnow()
        date = now.strftime("%Y%m%dT%H%M%SZ")
        # 2. 构造待签名字符串
        headers = {
            "Content-Type": "application/json;charset=utf8",
            "X-Project-Id": "",  # cn-north-4区域留空即可
            "X-Sdk-Date": date,
            "Host": f"dns.{self.region}.myhuaweicloud.com"
        }
        
        # 构造请求URI
        query_string = ""
        if params:
            query_items = sorted(params.items())
            query_string = "&".join([f"{k}={v}" for k, v in query_items])
        
        # 构造请求体（如果有）
        body_str = ""
        if body and method in ["POST", "PUT", "PATCH"]:
            body_str = json.dumps(body, separators=(',', ':'))  # 紧凑格式，无空格
        
        # 构造待签名的字符串（严格按华为云规范）
        sign_string = f"{method}\n{path}\n{query_string}\n{headers['Content-Type']}\n{headers['X-Sdk-Date']}\n"
        sign_string += body_str if body_str else ""
        
        # 3. 使用SK进行HMAC-SHA256签名
        signature = hmac.new(
            self.sk.encode('utf-8'),
            sign_string.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # 4. 构造Authorization头（适配cn-north-4区域）
        auth_header = f"SDK-HMAC-SHA256 Access={self.ak}, SignedHeaders=content-type;host;x-sdk-date, Signature={signature_b64}"
        headers["Authorization"] = auth_header
        
        return headers
    
    def _http_request(self, method, path, params=None, body=None):
        """发送HTTP请求并处理响应（增加重试机制）"""
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                url = f"{self.base_url}{path}"
                headers = self._sign_request(method, path, params, body)
                
                # 发送请求
                if method == "GET":
                    resp = requests.get(url, headers=headers, params=params, timeout=15)
                elif method == "DELETE":
                    resp = requests.delete(url, headers=headers, timeout=15)
                elif method == "POST":
                    resp = requests.post(url, headers=headers, json=body, timeout=15)
                else:
                    return {"code": 400, "message": f"不支持的请求方法：{method}"}
                
                # 处理响应
                if resp.status_code in [200, 201, 202, 204]:
                    try:
                        return {"code": 0, "data": resp.json() if resp.content else {}}
                    except:
                        return {"code": 0, "data": {}}
                elif resp.status_code == 401:
                    print(f"签名认证失败: {resp.text}，重试中...")
                    retry_count += 1
                    time.sleep(1)
                else:
                    return {
                        "code": resp.status_code,
                        "message": f"API请求失败: {resp.status_code} - {resp.text}"
                    }
            except requests.exceptions.RequestException as e:
                print(f"网络请求异常: {str(e)}，重试中...")
                retry_count += 1
                time.sleep(1)
        
        return {"code": 500, "message": f"请求重试{max_retries}次后仍失败"}
    
    def _get_all_zone_ids(self):
        """获取所有公网域名的zone_id映射（适配cn-north-4区域）"""
        path = "/publiczones"
        # 增加分页参数，确保获取所有域名
        params = {"limit": 100, "offset": 0}
        resp = self._http_request("GET", path, params=params)
        
        if resp["code"] != 0:
            print(f"获取域名列表失败: {resp['message']}，将使用手动配置的zone_id")
            return {}
        
        zone_map = {}
        for zone in resp["data"].get("zones", []):
            zone_map[zone["name"]] = zone["id"]
        return zone_map
    
    def get_zone_id(self, domain):
        """获取单个域名的zone_id（适配多级域名解析）"""
        # 处理多级域名（如official.platform.cname.itedev.com）
        domain_key = domain if domain.endswith('.') else f"{domain}."
        # 优先使用手动配置的zone_id，再用API获取的
        zone_id = self.manual_zone_ids.get(domain_key) or self.zone_ids.get(domain_key)
        
        if not zone_id:
            # 尝试去掉末尾的点再查
            domain_key_no_dot = domain_key.rstrip('.')
            zone_id = self.manual_zone_ids.get(domain_key_no_dot) or self.zone_ids.get(domain_key_no_dot)
        
        return zone_id
    
    def get_record_sets(self, domain, sub_domain, record_type):
        """获取指定域名、子域名、类型的记录集列表（适配多级域名）"""
        zone_id = self.get_zone_id(domain)
        if not zone_id:
            return {"code": 404, "message": f"域名{domain}不存在，zone_id未找到"}
        
        # 构造记录名称（适配多级域名）
        if sub_domain == '@':
            record_name = f"{domain}."
        else:
            # 处理多级子域名
            record_name = f"{sub_domain}.{domain}."
        
        # 调用API获取记录集（增加线路过滤）
        params = {
            "type": record_type,
            "name": record_name,
            "limit": 100
        }
        path = f"/publiczones/{zone_id}/recordsets"
        resp = self._http_request("GET", path, params=params)
        
        if resp["code"] != 0:
            return resp
        
        # 格式化返回结果
        result = {"code": 0, "data": {"records": []}}
        for record in resp["data"].get("recordsets", []):
            # 转换线路名称
            line = LINE_MAPPING.get(record.get("line", "default_view"), "default_view")
            # 为每个IP拆分记录
            for ip in record.get("records", []):
                result["data"]["records"].append({
                    "id": record["id"],
                    "line": line,
                    "value": ip,
                    "type": record["type"],
                    "ttl": record["ttl"],
                    "name": record["name"]
                })
        return result
    
    def delete_record_set(self, domain, recordset_id):
        """删除指定的记录集（适配cn-north-4区域）"""
        zone_id = self.get_zone_id(domain)
        if not zone_id:
            return {"code": 404, "message": f"域名{domain}不存在"}
        
        path = f"/publiczones/{zone_id}/recordsets/{recordset_id}"
        return self._http_request("DELETE", path)
    
    def create_record_set(self, domain, sub_domain, values, record_type, line, ttl):
        """创建单个记录集（适配cn-north-4区域）"""
        zone_id = self.get_zone_id(domain)
        if not zone_id:
            return {"code": 404, "message": f"域名{domain}不存在"}
        
        # 构造记录名称（适配多级域名）
        if sub_domain == '@':
            record_name = f"{domain}."
        else:
            record_name = f"{sub_domain}.{domain}."
        
        # 确保values是列表
        records = [values] if isinstance(values, str) else values
        # 转换线路编码
        line_code = LINE_MAPPING.get(line, "default_view")
        
        # 构造请求体（适配华为云DNS API规范）
        body = {
            "name": record_name,
            "type": record_type,
            "ttl": ttl,
            "records": records,
            "line": line_code,
            "description": "Auto updated by cf2dns script"  # 添加描述，便于识别
        }
        
        path = f"/publiczones/{zone_id}/recordsets"
        return self._http_request("POST", path, body=body)
    
    def batch_create_record_sets(self, domain, recordsets):
        """批量创建记录集（适配cn-north-4区域的批量API）"""
        zone_id = self.get_zone_id(domain)
        if not zone_id:
            return {"code": 404, "message": f"域名{domain}不存在"}
        
        # 构造批量请求体（严格适配华为云批量创建API格式）
        batch_body = {"recordsets": []}
        for rs in recordsets:
            # 转换线路编码
            line_code = LINE_MAPPING.get(rs["line"], "default_view")
            batch_body["recordsets"].append({
                "name": rs["name"],
                "type": rs["type"],
                "ttl": rs["ttl"],
                "records": rs["records"],
                "line": line_code,
                "description": "Auto updated by cf2dns script"
            })
        
        path = f"/publiczones/{zone_id}/recordsets/batch-create"
        return self._http_request("POST", path, body=batch_body)


def get_optimization_ip(iptype):
    """从两个API获取IP信息并合并"""
    try:
        merged_ips = {"CM": [], "CU": [], "CT": []}
        headers = {'Content-Type': 'application/json'}
        
        # 1. 从原API获取IP信息
        try:
            data = {"key": config["key"], "type": iptype}
            provider = next((p for p in provider_data if p.get('id') == config["data_server"]), None)
            if provider and provider.get('get_ip_url'):
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
            else:
                print("原API配置不完整，跳过")
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
        
        # 3. 去重（优化：保留完整信息，只去重IP）
        for isp in ["CM", "CU", "CT"]:
            seen_ips = set()
            unique_ips = []
            for ip_info in merged_ips[isp]:
                ip = ip_info.get("ip", "").strip()
                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip_info)
            merged_ips[isp] = unique_ips
        
        # 4. 按速度排序（优化：处理speed为None的情况）
        for isp in ["CM", "CU", "CT"]:
            merged_ips[isp].sort(key=lambda x: x.get("speed", 0) or 0, reverse=True)
        
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


def update_carrier_records(dns_api, domain, sub_domain, lines, all_ips, ttl):
    """更新移动、联通、电信的A和AAAA记录（适配多级域名）"""
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
            ret = dns_api.get_record_sets(domain, sub_domain, record_type)
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
                ret = dns_api.delete_record_set(domain, record_id)
                if ret.get("code") == 0:
                    print(f"✓ 删除旧{record_type}记录: {record_info['line']} - {record_info['ips']}")
                    deleted_count += 1
                else:
                    print(f"✗ 删除失败: {record_info['line']} - {ret.get('message', '未知错误')}")
        
        if deleted_count > 0:
            print(f"已删除 {deleted_count} 条旧记录")
        
        # 准备要批量创建的新记录集
        records_to_create = []
        # 构造完整记录名称（适配多级域名）
        if sub_domain == '@':
            full_name = f"{domain}."
        else:
            full_name = f"{sub_domain}.{domain}."
        
        # 处理配置中指定的线路
        for line in lines:
            if line not in line_mapping:
                continue  # 跳过非运营商线路
                
            line_chinese = line_mapping[line]
            
            # 获取新IP（IPv4）
            ip_list_v4 = []
            if all_ips.get("v4") and all_ips["v4"].get("code") == 200:
                ip_list_v4 = [ip["ip"] for ip in all_ips["v4"]["info"].get(line, [])]
                if ip_list_v4:
                    # 限制IP数量
                    ip_list_v4 = ip_list_v4[:config["affect_num"]]
                    # 添加A记录集
                    records_to_create.append({
                        "name": full_name,
                        "type": "A",
                        "records": ip_list_v4,
                        "ttl": ttl,
                        "line": line_chinese
                    })
            
            # 获取新IP（IPv6）
            ip_list_v6 = []
            if all_ips.get("v6") and all_ips["v6"].get("code") == 200:
                ip_list_v6 = [ip["ip"] for ip in all_ips["v6"]["info"].get(line, [])]
                if ip_list_v6:
                    # 限制IP数量
                    ip_list_v6 = ip_list_v6[:config["affect_num"]]
                    # 添加AAAA记录集
                    records_to_create.append({
                        "name": full_name,
                        "type": "AAAA",
                        "records": ip_list_v6,
                        "ttl": ttl,
                        "line": line_chinese
                    })
        
        # 批量创建新记录集
        if records_to_create:
            ret = dns_api.batch_create_record_sets(domain, records_to_create)
            # 判断是否成功
            if ret.get("code") == 0:
                print(f"✓ 批量创建成功，创建了 {len(records_to_create)} 条记录集")
                for rs in records_to_create:
                    print(f"  - {rs['type']} {rs['line']}: {rs['records']}")
                if "task_id" in ret.get("data", {}):
                    print(f"  任务ID: {ret['data']['task_id']}")
            else:
                print(f"✗ 批量创建失败: {ret.get('message', '未知错误')}")
        else:
            print("没有需要创建的新记录")
        
        print(f"完成 {domain} - {sub_domain} 的运营商记录更新\n")
        
    except Exception as e:
        print(f"更新记录时出错: {e}")
        traceback.print_exc()


def main():
    """主函数（适配cn-north-4区域和指定域名）"""
    # 强制设置区域为cn-north-4（覆盖配置）
    config["region_hw"] = "cn-north-4"
    
    if not DOMAINS or len(DOMAINS) == 0:
        # 若未配置域名，默认使用控制台域名
        DOMAINS = {
            "official.platform.cname.itedev.com": {
                "@": ["CM", "CU", "CT"]
            }
        }
        print(f"未配置域名，默认使用: {list(DOMAINS.keys())[0]}")
    
    # 验证关键配置
    if not config.get("secretid") or not config.get("secretkey"):
        print("错误：华为云密钥配置不完整")
        sys.exit(1)
    
    # 初始化华为云DNS API客户端
    try:
        dns_api = HuaweiDNSAPI(
            config["secretid"],
            config["secretkey"],
            config["region_hw"]
        )
        # 打印zone_id信息，便于调试
        print(f"已加载zone_id映射: {dns_api.zone_ids}")
        if not dns_api.zone_ids:
            print("警告：未获取到任何域名的zone_id，请检查AK/SK权限和区域配置")
    except Exception as e:
        print(f"初始化DNS API客户端失败: {e}")
        sys.exit(1)
    
    print("=" * 60)
    print("开始更新移动、联通、电信的A和AAAA记录")
    print(f"区域: {config['region_hw']} | 域名: {list(DOMAINS.keys())[0]}")
    print("（删除旧记录 + 批量添加新记录）")
    print("其他线路（境外、默认）保持不变")
    print("=" * 60)
    
    # 分别获取IPv4和IPv6的IP
    all_ips = {"v4": None, "v6": None}
    
    if config.get("ipv4") == "on":
        print("\n开始获取IPv4优化IP...")
        all_ips["v4"] = get_optimization_ip("v4")
        if all_ips["v4"]:
            print(f"IPv4 IP数量 - 移动:{len(all_ips['v4']['info']['CM'])} 联通:{len(all_ips['v4']['info']['CU'])} 电信:{len(all_ips['v4']['info']['CT'])}")
        else:
            print("获取IPv4 IP失败")
    
    if config.get("ipv6") == "on":
        print("\n开始获取IPv6优化IP...")
        all_ips["v6"] = get_optimization_ip("v6")
        if all_ips["v6"]:
            print(f"IPv6 IP数量 - 移动:{len(all_ips['v6']['info']['CM'])} 联通:{len(all_ips['v6']['info']['CU'])} 电信:{len(all_ips['v6']['info']['CT'])}")
        else:
            print("获取IPv6 IP失败")
    
    # 检查是否获取到IP
    if not all_ips["v4"] and not all_ips["v6"]:
        print("错误：未获取到任何IP地址，程序退出")
        sys.exit(1)
    
    # 遍历所有域名和子域名
    for domain, sub_domains in DOMAINS.items():
        for sub_domain, lines in sub_domains.items():
            # 检查是否有运营商线路
            has_carrier = any(line in ["CM", "CU", "CT"] for line in lines)
            if has_carrier:
                update_carrier_records(dns_api, domain, sub_domain, lines, all_ips, config["ttl"])
            else:
                print(f"跳过 {domain} - {sub_domain}（没有配置运营商线路）")


if __name__ == '__main__':
    try:
        main()
        print("\n程序执行完成")
    except Exception as e:
        print(f"程序执行失败: {e}")
        traceback.print_exc()
        sys.exit(1)