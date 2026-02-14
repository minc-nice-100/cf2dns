#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

"""
自动安装依赖脚本
运行此脚本会自动安装所需的华为云SDK依赖
"""

import sys
import os
import subprocess
import importlib.util
import time
import json
import requests
import traceback

# ========== 自动安装依赖 ==========
def install_package(package_name, import_name=None):
    """安装Python包"""
    if import_name is None:
        import_name = package_name
    
    # 检查是否已安装
    if importlib.util.find_spec(import_name) is not None:
        print(f"✓ {package_name} 已安装")
        return True
    
    print(f"正在安装 {package_name}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", package_name])
        print(f"✓ {package_name} 安装成功")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {package_name} 安装失败: {e}")
        return False

def install_dependencies():
    """安装所有依赖"""
    print("=" * 60)
    print("检查并安装依赖包...")
    print("=" * 60)
    
    dependencies = [
        ("requests", "requests"),
        ("huaweicloudsdkcore", "huaweicloudsdkcore"),
        ("huaweicloudsdkdns", "huaweicloudsdkdns")
    ]
    
    all_success = True
    for package, import_name in dependencies:
        if not install_package(package, import_name):
            all_success = False
    
    if not all_success:
        print("\n✗ 部分依赖安装失败，请手动安装:")
        print("  pip install requests huaweicloudsdkcore huaweicloudsdkdns")
        sys.exit(1)
    
    print("\n✓ 所有依赖安装完成")
    print("=" * 60)

# 在主程序运行前安装依赖
if not os.environ.get("_DEP_INSTALLED"):
    os.environ["_DEP_INSTALLED"] = "1"
    install_dependencies()

# ========== 现在导入SDK ==========
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion
from huaweicloudsdkdns.v2 import *
from huaweicloudsdkcore.exceptions import exceptions

# ========== 配置加载 ==========
config = json.loads(os.environ["CONFIG"])
# 支持的线路类型:
# CM:移动 CU:联通 CT:电信 AB:境外 DEF:默认 EDU:教育网 TLT:铁通 PBS:鹏博士
DOMAINS = json.loads(os.environ["DOMAINS"])
provider_data = json.loads(os.environ["PROVIDER"])

# ========== 华为云DNS客户端 ==========
class HuaWeiDNSClient:
    """华为云DNS客户端封装，支持批量操作"""
    
    def __init__(self, ak, sk, region_id):
        """初始化华为云DNS客户端"""
        try:
            credentials = BasicCredentials(ak, sk)
            self.client = DnsClient.new_builder() \
                .with_credentials(credentials) \
                .with_region(DnsRegion.value_of(region_id)) \
                .build()
            print(f"✓ 华为云客户端初始化成功，区域: {region_id}")
        except Exception as e:
            print(f"✗ 华为云客户端初始化失败: {str(e)}")
            raise
    
    def get_zone_id(self, domain_name):
        """根据域名获取zone_id"""
        try:
            request = ListPublicZonesRequest()
            request.name = domain_name.rstrip('.')
            response = self.client.list_public_zones(request)
            
            if response.zones and len(response.zones) > 0:
                for zone in response.zones:
                    if zone.name.rstrip('.') == domain_name.rstrip('.'):
                        return zone.id
            return None
        except Exception as e:
            print(f"获取zone_id失败: {str(e)}")
            return None
    
    def get_existing_records(self, zone_id, record_name, record_type):
        """获取现有的记录集，按线路分类"""
        try:
            request = ListRecordSetsWithLineRequest()
            request.zone_id = zone_id
            request.name = record_name.rstrip('.') + '.'  # 确保格式正确
            request.type = record_type
            
            response = self.client.list_record_sets_with_line(request)
            
            # 按线路分类
            records_by_line = {}
            for record in response.recordsets:
                line = record.line
                if line not in records_by_line:
                    records_by_line[line] = []
                
                records_by_line[line].append({
                    "id": record.id,
                    "records": record.records,
                    "ttl": record.ttl
                })
            
            return records_by_line
        except Exception as e:
            print(f"获取现有记录失败: {str(e)}")
            return {}
    
    def safe_delete_records(self, zone_id, delete_ids, line_name):
        """安全删除记录，带重试机制"""
        if not delete_ids:
            return True
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                del_request = BatchDeleteRecordSetRequest()
                del_request.zone_id = zone_id
                del_request.body = BatchDeleteRecordSetRequestBody(
                    recordset_ids=delete_ids
                )
                self.client.batch_delete_record_set(del_request)
                print(f"  删除线路 {line_name} 的 {len(delete_ids)} 个记录集成功")
                return True
            except exceptions.ClientRequestException as e:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2
                    print(f"  删除失败，{wait_time}秒后重试: {e.error_msg}")
                    time.sleep(wait_time)
                else:
                    print(f"  删除失败，已达最大重试次数: {e.error_msg}")
                    return False
            except Exception as e:
                print(f"  删除异常: {str(e)}")
                return False
        return False
    
    def safe_create_record(self, zone_id, name, record_type, line, ip_list, ttl):
        """安全创建记录集，带重试机制"""
        if not ip_list:
            return False
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                create_request = CreateRecordSetRequest()
                create_request.zone_id = zone_id
                
                create_request.body = CreateRecordSetRequestBody(
                    name=name.rstrip('.') + '.',
                    type=record_type,
                    records=ip_list,
                    line=line,
                    ttl=ttl,
                    description=f"Auto updated at {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
                
                response = self.client.create_record_set(create_request)
                print(f"  ✓ 创建记录集成功: 线路 {line}, IP数量 {len(ip_list)}")
                print(f"    记录集ID: {response.id}")
                return True
                
            except exceptions.ClientRequestException as e:
                if "already exists" in e.error_msg.lower():
                    print(f"  记录集已存在，将尝试先删除")
                    # 尝试删除现有记录
                    existing = self.get_existing_records(zone_id, name, record_type)
                    if line in existing:
                        delete_ids = [r["id"] for r in existing[line]]
                        if delete_ids:
                            self.safe_delete_records(zone_id, delete_ids, line)
                            time.sleep(2)
                            continue
                
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2
                    print(f"  创建失败，{wait_time}秒后重试: {e.error_msg}")
                    time.sleep(wait_time)
                else:
                    print(f"  ✗ 创建失败，已达最大重试次数: {e.error_msg}")
                    return False
            except Exception as e:
                print(f"  ✗ 创建异常: {str(e)}")
                return False
        return False
    
    def batch_update_line(self, zone_id, name, record_type, line, ip_list, ttl):
        """
        更新单个线路的记录集
        """
        try:
            # 获取现有记录
            existing = self.get_existing_records(zone_id, name, record_type)
            
            # 如果该线路已有记录，先删除
            if line in existing and existing[line]:
                delete_ids = [r["id"] for r in existing[line]]
                if not self.safe_delete_records(zone_id, delete_ids, line):
                    print(f"  ⚠ 删除失败，但继续尝试创建")
                time.sleep(1)
            
            # 创建新记录
            if ip_list:
                return self.safe_create_record(zone_id, name, record_type, line, ip_list, ttl)
            else:
                print(f"  线路 {line} 无IP，跳过创建")
                return True
                
        except Exception as e:
            print(f"  ✗ 更新线路 {line} 失败: {str(e)}")
            traceback.print_exc()
            return False
    
    def batch_update_all_lines(self, zone_id, name, record_type, line_ip_mapping, ttl, protected_lines=None):
        """
        批量更新所有线路的记录
        
        Args:
            protected_lines: 受保护的线路列表，这些线路不会被修改
        """
        if protected_lines is None:
            protected_lines = ["境外"]  # 默认保护境外线路
        
        results = []
        
        # 先获取所有现有记录，用于检查受保护的线路
        existing = self.get_existing_records(zone_id, name, record_type)
        
        # 检查受保护的线路
        for protected_line in protected_lines:
            if protected_line in existing and existing[protected_line]:
                print(f"\n  ⚠ 检测到受保护的线路: {protected_line}")
                print(f"    现有记录: {[r['records'] for r in existing[protected_line]]}")
                print(f"    根据要求，不修改境外记录")
        
        # 更新指定的线路
        for line, ip_list in line_ip_mapping.items():
            # 跳过受保护的线路
            if line in protected_lines:
                print(f"\n  跳过受保护的线路: {line}")
                continue
            
            print(f"\n  处理线路: {line}")
            result = self.batch_update_line(zone_id, name, record_type, line, ip_list, ttl)
            results.append(result)
        
        return all(results)

# ========== API请求函数 ==========
def get_optimization_ip():
    """从指定API获取优选IP - 适配新API格式"""
    try:
        headers = {'Content-Type': 'application/json'}
        data = {"key": config["key"], "type": iptype}
        provider = [item for item in provider_data if item['id'] == config["data_server"]][0]
        
        print(f"请求API: {provider['get_ip_url']}")
        print(f"请求数据: {data}")
        
        response = requests.post(provider['get_ip_url'], json=data, headers=headers, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            print(f"API返回成功，数据长度: {len(json.dumps(result))}")
            return result
        else:
            print(f"获取优选IP失败: HTTP状态码 {response.status_code}")
            return None
    except Exception as e:
        print(f"获取优选IP异常: {str(e)}")
        traceback.print_exc()
        return None

def extract_ips_from_api_response(api_response, line_type):
    """
    从API响应中提取指定线路的IP列表
    适配API格式: response.success.data.v4.CM[].ip
    """
    try:
        if not api_response or not api_response.get("success"):
            print(f"API响应未返回成功状态")
            return []
        
        data = api_response.get("data", {})
        if not data:
            print("API响应中无data字段")
            return []
        
        # 根据IP类型选择v4或v6
        ip_data = data.get(iptype, {})
        if not ip_data:
            print(f"API响应中无 {iptype} 数据")
            return []
        
        # 线路映射
        line_mapping = {
            "CM": "CM",      # 移动
            "CU": "CU",      # 联通
            "CT": "CT",      # 电信
            "EDU": "CT",     # 教育网 -> 回退到电信
            "TLT": "CT",     # 铁通 -> 回退到电信
            "PBS": "CT",     # 鹏博士 -> 回退到电信
            "AB": "CT",      # 境外 -> 也使用电信作为数据源，但实际不会修改
            "DEF": "CT"      # 默认 -> 使用电信
        }
        
        api_line = line_mapping.get(line_type, "CT")
        line_ips = ip_data.get(api_line, [])
        
        if not line_ips:
            print(f"线路 {line_type} (API映射: {api_line}) 无IP数据")
            return []
        
        # 提取IP地址
        ip_list = []
        for item in line_ips:
            if isinstance(item, dict) and "ip" in item:
                ip_list.append(item["ip"])
        
        print(f"线路 {line_type} 提取到 {len(ip_list)} 个IP")
        return ip_list
        
    except Exception as e:
        print(f"提取IP列表异常: {str(e)}")
        traceback.print_exc()
        return []

# ========== 主函数 ==========
def main():
    """主函数"""
    global iptype, config
    
    # 初始化华为云客户端
    try:
        cloud = HuaWeiDNSClient(config["secretid"], config["secretkey"], config["region_hw"])
    except Exception as e:
        print(f"初始化华为云客户端失败: {str(e)}")
        return
    
    # 线路名称映射 (英文代码 -> 中文名称)
    line_name_mapping = {
        "CM": "移动",
        "CU": "联通", 
        "CT": "电信",
        "EDU": "教育网",
        "TLT": "铁通",
        "PBS": "鹏博士",
        "AB": "境外",
        "DEF": "默认"
    }
    
    # 受保护的线路（不会被修改）
    protected_lines = ["境外"]
    
    # 处理IPv4和IPv6
    for ip_version in ["v4", "v6"]:
        if config.get(f"ip{ip_version}") == "on":
            iptype = ip_version
            record_type = "AAAA" if ip_version == "v6" else "A"
            
            print(f"\n{'='*60}")
            print(f"开始处理{ip_version.upper()}记录")
            print(f"{'='*60}")
            
            # 获取优选IP
            api_response = get_optimization_ip()
            if not api_response:
                print(f"获取优选IP失败，跳过{ip_version.upper()}处理")
                continue
            
            # 提取各线路IP
            ip_pool = {}
            for line_code in ["CM", "CU", "CT", "EDU", "TLT", "PBS", "AB", "DEF"]:
                ip_pool[line_code] = extract_ips_from_api_response(api_response, line_code)
            
            print(f"\nIP统计:")
            print(f"  移动(CM): {len(ip_pool['CM'])} 个")
            print(f"  联通(CU): {len(ip_pool['CU'])} 个")
            print(f"  电信(CT): {len(ip_pool['CT'])} 个")
            print(f"  教育网(EDU): {len(ip_pool['EDU'])} 个 (回退到电信)")
            print(f"  铁通(TLT): {len(ip_pool['TLT'])} 个 (回退到电信)")
            print(f"  鹏博士(PBS): {len(ip_pool['PBS'])} 个 (回退到电信)")
            print(f"  境外(AB): {len(ip_pool['AB'])} 个 (受保护，不修改)")
            print(f"  默认(DEF): {len(ip_pool['DEF'])} 个")
            
            # 处理每个域名
            for domain, sub_domains in DOMAINS.items():
                print(f"\n处理域名: {domain}")
                
                # 获取zone_id
                zone_id = cloud.get_zone_id(domain)
                if not zone_id:
                    print(f"  获取zone_id失败，跳过域名 {domain}")
                    continue
                print(f"  zone_id: {zone_id}")
                
                for sub_domain, lines in sub_domains.items():
                    full_record_name = f"{sub_domain}.{domain}" if sub_domain else domain
                    print(f"\n  子域名: {full_record_name}")
                    
                    # 构建线路到IP列表的映射
                    line_ip_mapping = {}
                    
                    for line_code in lines:
                        # 获取中文线路名
                        chinese_line = line_name_mapping.get(line_code, line_code)
                        
                        # 根据线路类型决定使用的IP
                        if line_code == "AB":  # 境外 - 不修改，跳过
                            print(f"    线路 {chinese_line} 是境外线路，根据要求不修改")
                            continue
                        elif line_code in ["EDU", "TLT", "PBS"]:  # 教育网、铁通、鹏博士 - 回退到电信
                            line_ip_mapping[chinese_line] = ip_pool["CT"]
                            print(f"    线路 {chinese_line} 使用电信IP回退")
                        elif line_code == "DEF":  # 默认
                            line_ip_mapping[chinese_line] = ip_pool["CT"]
                        elif line_code in ip_pool:  # 移动、联通、电信
                            line_ip_mapping[chinese_line] = ip_pool[line_code]
                        else:
                            print(f"    未知线路 {line_code}，跳过")
                    
                    # 批量更新
                    if line_ip_mapping:
                        print(f"\n    准备更新的线路: {list(line_ip_mapping.keys())}")
                        cloud.batch_update_all_lines(
                            zone_id, 
                            full_record_name, 
                            record_type, 
                            line_ip_mapping, 
                            config["ttl"],
                            protected_lines=protected_lines
                        )
                    else:
                        print(f"    没有需要更新的线路")

if __name__ == '__main__':
    # 显示启动信息
    print("="*60)
    print(f"脚本启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"DNS服务商: 华为云 (ID: {config.get('dns_server')})")
    print(f"IPv4启用: {config.get('ipv4')}")
    print(f"IPv6启用: {config.get('ipv6')}")
    print(f"TTL: {config.get('ttl')}")
    print(f"数据源: {config.get('data_server')}")
    print("="*60)
    print("线路处理规则:")
    print("  - 移动/联通/电信: 使用对应线路IP")
    print("  - 教育网/铁通/鹏博士: 回退到电信IP")
    print("  - 境外: 不修改（受保护）")
    print("  - 默认: 使用电信IP")
    print("="*60)
    
    # 验证DNS服务商
    if config["dns_server"] != 3:
        print(f"✗ 错误: 当前DNS服务商ID为 {config['dns_server']}，但本脚本仅支持华为云(ID=3)")
        sys.exit(1)
    
    # 执行主函数
    try:
        main()
    except Exception as e:
        print(f"脚本执行异常: {str(e)}")
        traceback.print_exc()
    
    print(f"\n{'='*60}")
    print(f"脚本执行完成: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
