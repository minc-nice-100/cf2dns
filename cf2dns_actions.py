#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com
# 纯HTTP请求实现华为云DNS记录更新（最终稳定版）

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

# ======================== 全局配置 ========================
# 新的API地址
NEW_API_URL = "https://api.4ce.cn/api/bestCFIP"

# 华为云DNS线路映射
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

# 控制台配置（固定值）
CONSOLE_ZONE_ID = "ff8080829a978db4019b3af3e7093a8c"
CONSOLE_DOMAIN = "official.platform.cname.itedev.com"
CONSOLE_REGION = "cn-north-4"

# ======================== 配置加载 ========================
def load_config():
    """安全加载所有配置，避免变量作用域问题"""
    # 默认配置
    default_config = {
        "key": "",
        "data_server": "",
        "secretid": "",  # 华为云AK
        "secretkey": "", # 华为云SK
        "region_hw": CONSOLE_REGION,
        "ipv4": "on",
        "ipv6": "off",
        "affect_num": 5,
        "ttl": 600
    }
    
    # 加载环境变量
    try:
        env_config = json.loads(os.environ.get("CONFIG", "{}"))
        config = {**default_config, **env_config}
    except json.JSONDecodeError as e:
        print(f"CONFIG环境变量解析失败，使用默认配置: {e}")
        config = default_config
    
    # 加载域名配置
    try:
        domains = json.loads(os.environ.get("DOMAINS", "{}"))
        # 如果未配置域名，使用控制台默认域名
        if not domains or len(domains) == 0:
            domains = {
                CONSOLE_DOMAIN: {
                    "@": ["CM", "CU", "CT"]
                }
            }
            print(f"DOMAINS环境变量未配置，使用默认域名: {CONSOLE_DOMAIN}")
    except json.JSONDecodeError as e:
        print(f"DOMAINS环境变量解析失败，使用默认域名配置: {e}")
        domains = {
            CONSOLE_DOMAIN: {
                "@": ["CM", "CU", "CT"]
            }
        }
    
    # 加载PROVIDER配置
    try:
        provider_data = json.loads(os.environ.get("PROVIDER", "[]"))
    except json.JSONDecodeError as e:
        print(f"PROVIDER环境变量解析失败，使用空配置: {e}")
        provider_data = []
    
    return config, domains, provider_data

# ======================== 华为云DNS API ========================
class HuaweiDNSAPI:
    """华为云DNS API封装（纯HTTP请求版）"""
    
    def __init__(self, ak, sk, region):
        self.ak = ak
        self.sk = sk
        self.region = region
        self.base_url = f"https://dns.{region}.myhuaweicloud.com/v2"
        # 预加载控制台ZoneID
        self.zone_ids = {
            f"{CONSOLE_DOMAIN}.": CONSOLE_ZONE_ID,
            CONSOLE_DOMAIN: CONSOLE_ZONE_ID
        }
        # 补充API获取的ZoneID
        api_zone_ids = self._get_all_zone_ids()
        self.zone_ids.update(api_zone_ids)
    
    def _sign_request(self, method, path, params=None, body=None):
        """生成华为云API请求签名"""
        now = datetime.utcnow()
        date = now.strftime("%Y%m%dT%H%M%SZ")
        
        headers = {
            "Content-Type": "application/json;charset=utf8",
            "X-Project-Id": "",
            "X-Sdk-Date": date,
            "Host": f"dns.{self.region}.myhuaweicloud.com"
        }
        
        # 构造查询字符串
        query_string = ""
        if params:
            query_items = sorted(params.items())
            query_string = "&".join([f"{k}={v}" for k, v in query_items])
        
        # 构造请求体
        body_str = ""
        if body and method in ["POST", "PUT", "PATCH"]:
            body_str = json.dumps(body, separators=(',', ':'))
        
        # 生成签名
        sign_string = f"{method}\n{path}\n{query_string}\n{headers['Content-Type']}\n{headers['X-Sdk-Date']}\n{body_str}"
        signature = hmac.new(
            self.sk.encode('utf-8'),
            sign_string.encode('utf-8'),
            hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # 构造认证头
        headers["Authorization"] = (
            f"SDK-HMAC-SHA256 Access={self.ak}, "
            f"SignedHeaders=content-type;host;x-sdk-date, "
            f"Signature={signature_b64}"
        )
        
        return headers
    
    def _http_request(self, method, path, params=None, body=None):
        """发送HTTP请求（带重试）"""
        max_retries = 3
        for retry in range(max_retries):
            try:
                url = f"{self.base_url}{path}"
                headers = self._sign_request(method, path, params, body)
                
                if method == "GET":
                    resp = requests.get(url, headers=headers, params=params, timeout=15)
                elif method == "DELETE":
                    resp = requests.delete(url, headers=headers, timeout=15)
                elif method == "POST":
                    resp = requests.post(url, headers=headers, json=body, timeout=15)
                else:
                    return {"code": 400, "message": f"不支持的请求方法：{method}"}
                
                if resp.status_code in [200, 201, 202, 204]:
                    return {"code": 0, "data": resp.json() if resp.content else {}}
                elif resp.status_code == 401 and retry < max_retries - 1:
                    print(f"认证失败，重试({retry+1}/{max_retries}): {resp.text}")
                    time.sleep(1)
                else:
                    return {
                        "code": resp.status_code,
                        "message": f"API错误 {resp.status_code}: {resp.text}"
                    }
            except Exception as e:
                if retry < max_retries - 1:
                    print(f"请求异常，重试({retry+1}/{max_retries}): {str(e)}")
                    time.sleep(1)
                else:
                    return {"code": 500, "message": f"请求失败: {str(e)}"}
        
        return {"code": 500, "message": "达到最大重试次数"}
    
    def _get_all_zone_ids(self):
        """获取所有ZoneID"""
        try:
            resp = self._http_request("GET", "/publiczones", params={"limit": 100})
            if resp["code"] != 0:
                print(f"获取ZoneID失败: {resp['message']}")
                return {}
            
            zone_map = {}
            for zone in resp["data"].get("zones", []):
                zone_map[zone["name"]] = zone["id"]
                zone_map[zone["name"].rstrip('.')] = zone["id"]
            return zone_map
        except Exception as e:
            print(f"获取ZoneID异常: {str(e)}")
            return {}
    
    def get_zone_id(self, domain):
        """获取域名对应的ZoneID"""
        # 多种格式匹配
        domain_formats = [
            domain,
            f"{domain}.",
            domain.lower(),
            f"{domain.lower()}."
        ]
        
        for fmt in domain_formats:
            if fmt in self.zone_ids:
                return self.zone_ids[fmt]
        
        print(f"未找到域名 {domain} 的ZoneID，使用控制台默认值")
        return CONSOLE_ZONE_ID
    
    def get_record_sets(self, domain, sub_domain, record_type):
        """获取记录集列表"""
        zone_id = self.get_zone_id(domain)
        if sub_domain == '@':
            record_name = f"{domain}."
        else:
            record_name = f"{sub_domain}.{domain}."
        
        params = {"type": record_type, "name": record_name, "limit": 100}
        resp = self._http_request("GET", f"/publiczones/{zone_id}/recordsets", params=params)
        
        if resp["code"] != 0:
            return resp
        
        # 格式化结果
        result = {"code": 0, "data": {"records": []}}
        for record in resp["data"].get("recordsets", []):
            line = LINE_MAPPING.get(record.get("line"), "default_view")
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
        """删除记录集"""
        zone_id = self.get_zone_id(domain)
        return self._http_request("DELETE", f"/publiczones/{zone_id}/recordsets/{recordset_id}")
    
    def batch_create_record_sets(self, domain, recordsets):
        """批量创建记录集"""
        zone_id = self.get_zone_id(domain)
        batch_body = {"recordsets": []}
        
        for rs in recordsets:
            batch_body["recordsets"].append({
                "name": rs["name"],
                "type": rs["type"],
                "ttl": rs["ttl"],
                "records": rs["records"],
                "line": LINE_MAPPING.get(rs["line"], "default_view"),
                "description": "Auto updated by cf2dns"
            })
        
        return self._http_request("POST", f"/publiczones/{zone_id}/recordsets/batch-create", body=batch_body)

# ======================== IP获取 ========================
def get_optimization_ip(iptype, config, provider_data):
    """获取优化IP"""
    merged_ips = {"CM": [], "CU": [], "CT": []}
    headers = {'Content-Type': 'application/json'}
    
    # 1. 原API
    try:
        data = {"key": config["key"], "type": iptype}
        provider = next((p for p in provider_data if p.get('id') == config["data_server"]), None)
        if provider and provider.get('get_ip_url'):
            resp = requests.post(provider['get_ip_url'], json=data, headers=headers, timeout=10)
            if resp.status_code == 200:
                old_data = resp.json()
                if old_data.get("code") == 200:
                    for isp in ["CM", "CU", "CT"]:
                        for ip_info in old_data["info"].get(isp, []):
                            if isinstance(ip_info, str):
                                ip_info = {"ip": ip_info}
                            elif "value" in ip_info and "ip" not in ip_info:
                                ip_info["ip"] = ip_info["value"]
                            merged_ips[isp].append(ip_info)
    except Exception as e:
        print(f"原API获取{iptype}失败: {str(e)}")
    
    # 2. 新API
    try:
        resp = requests.get(NEW_API_URL, timeout=10)
        if resp.status_code == 200:
            new_data = resp.json()
            if new_data.get("success") and iptype in new_data.get("data", {}):
                for isp in ["CM", "CU", "CT"]:
                    for ip_info in new_data["data"][iptype].get(isp, []):
                        merged_ips[isp].append({
                            "ip": ip_info["ip"],
                            "speed": ip_info.get("speed", 0)
                        })
    except Exception as e:
        print(f"新API获取{iptype}失败: {str(e)}")
    
    # 去重和排序
    for isp in ["CM", "CU", "CT"]:
        seen = set()
        unique = []
        for ip_info in merged_ips[isp]:
            ip = ip_info.get("ip", "").strip()
            if ip and ip not in seen:
                seen.add(ip)
                unique.append(ip_info)
        # 按速度排序
        unique.sort(key=lambda x: x.get("speed", 0) or 0, reverse=True)
        merged_ips[isp] = unique[:config["affect_num"]]
    
    total = sum(len(merged_ips[isp]) for isp in ["CM", "CU", "CT"])
    print(f"获取{iptype} IP总数: {total} (移动:{len(merged_ips['CM'])} 联通:{len(merged_ips['CU'])} 电信:{len(merged_ips['CT'])})")
    
    return {"code": 200, "info": merged_ips} if total > 0 else None

# ======================== 记录更新 ========================
def update_carrier_records(dns_api, domain, sub_domain, lines, all_ips, config):
    """更新运营商记录"""
    line_mapping = {"CM": "移动", "CU": "联通", "CT": "电信"}
    record_types = ["A", "AAAA"] if config["ipv6"] == "on" else ["A"]
    
    print(f"\n=== 更新 {domain} - {sub_domain} ===")
    
    # 1. 获取并删除旧记录
    existing_records = {"A": {}, "AAAA": {}}
    deleted_count = 0
    
    for rtype in record_types:
        ret = dns_api.get_record_sets(domain, sub_domain, rtype)
        if ret["code"] != 0:
            print(f"获取{rtype}记录失败: {ret['message']}")
            continue
        
        for record in ret["data"]["records"]:
            if record["line"] in ["移动", "联通", "电信"]:
                rid = record["id"]
                existing_records[rtype][rid] = {"line": record["line"], "ip": record["value"]}
    
    # 删除旧记录
    for rtype in record_types:
        for rid, info in existing_records[rtype].items():
            ret = dns_api.delete_record_set(domain, rid)
            if ret["code"] == 0:
                print(f"✓ 删除 {rtype} {info['line']}: {info['ip']}")
                deleted_count += 1
            else:
                print(f"✗ 删除失败 {rtype} {info['line']}: {ret['message']}")
    
    if deleted_count > 0:
        print(f"共删除 {deleted_count} 条旧记录")
    
    # 2. 创建新记录
    records_to_create = []
    full_name = f"{domain}." if sub_domain == '@' else f"{sub_domain}.{domain}."
    
    for line in lines:
        if line not in line_mapping:
            continue
        
        line_cn = line_mapping[line]
        
        # IPv4记录
        if config["ipv4"] == "on" and all_ips.get("v4"):
            ips = [ip["ip"] for ip in all_ips["v4"]["info"].get(line, [])]
            if ips:
                records_to_create.append({
                    "name": full_name,
                    "type": "A",
                    "records": ips,
                    "ttl": config["ttl"],
                    "line": line_cn
                })
        
        # IPv6记录
        if config["ipv6"] == "on" and all_ips.get("v6"):
            ips = [ip["ip"] for ip in all_ips["v6"]["info"].get(line, [])]
            if ips:
                records_to_create.append({
                    "name": full_name,
                    "type": "AAAA",
                    "records": ips,
                    "ttl": config["ttl"],
                    "line": line_cn
                })
    
    # 批量创建
    if records_to_create:
        ret = dns_api.batch_create_record_sets(domain, records_to_create)
        if ret["code"] == 0:
            print(f"\n✓ 批量创建成功 ({len(records_to_create)} 条)")
            for rs in records_to_create:
                print(f"  - {rs['type']} {rs['line']}: {rs['records']}")
            if "task_id" in ret["data"]:
                print(f"  任务ID: {ret['data']['task_id']}")
        else:
            print(f"\n✗ 批量创建失败: {ret['message']}")
    else:
        print("\n✓ 无新记录需要创建")

# ======================== 主函数 ========================
def main():
    """主函数（无任何作用域问题）"""
    # 1. 加载配置
    config, domains, provider_data = load_config()
    
    # 2. 验证密钥
    if not config["secretid"] or not config["secretkey"]:
        print("❌ 错误：华为云AK/SK未配置")
        sys.exit(1)
    
    # 3. 初始化DNS客户端
    try:
        dns_api = HuaweiDNSAPI(config["secretid"], config["secretkey"], config["region_hw"])
        print(f"✅ DNS客户端初始化成功 (区域: {config['region_hw']})")
        print(f"✅ 已加载ZoneID: {dns_api.zone_ids}")
    except Exception as e:
        print(f"❌ DNS客户端初始化失败: {str(e)}")
        sys.exit(1)
    
    # 4. 获取优化IP
    all_ips = {}
    if config["ipv4"] == "on":
        all_ips["v4"] = get_optimization_ip("v4", config, provider_data)
    if config["ipv6"] == "on":
        all_ips["v6"] = get_optimization_ip("v6", config, provider_data)
    
    # 检查IP是否获取成功
    if not any(all_ips.values()):
        print("❌ 错误：未获取到任何IP地址")
        sys.exit(1)
    
    # 5. 更新所有域名记录
    for domain, sub_domains in domains.items():
        for sub_domain, lines in sub_domains.items():
            update_carrier_records(dns_api, domain, sub_domain, lines, all_ips, config)
    
    print("\n========================")
    print("✅ 所有操作执行完成")
    print("========================")

# ======================== 入口 ========================
if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ 程序执行失败: {str(e)}")
        traceback.print_exc()
        sys.exit(1)