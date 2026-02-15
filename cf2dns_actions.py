#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys
import os
import json
import requests
import time
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


def delete_carrier_records(cloud, domain, sub_domain):
    """删除移动、联通、电信的所有A和AAAA记录"""
    try:
        # 要删除的线路
        carrier_lines = ["移动", "联通", "电信"]
        # 要删除的记录类型
        record_types = ["A", "AAAA"]
        
        print(f"\n开始删除 {domain} - {sub_domain} 的运营商记录...")
        
        for record_type in record_types:
            # 获取当前记录
            ret = cloud.get_record(domain, 100, sub_domain, record_type)
            
            if ret.get("code") != 0:
                print(f"获取{record_type}记录失败: {ret.get('message', '未知错误')}")
                continue
            
            records_to_delete = []
            for record in ret.get("data", {}).get("records", []):
                if record["line"] in carrier_lines:
                    records_to_delete.append(record)
            
            if not records_to_delete:
                print(f"没有找到需要删除的{record_type}记录")
                continue
            
            # 按记录集ID分组（同一个记录集可能有多个IP）
            records_by_id = {}
            for record in records_to_delete:
                if record["id"] not in records_by_id:
                    records_by_id[record["id"]] = []
                records_by_id[record["id"]].append(record)
            
            # 删除每个记录集
            for record_id, records in records_by_id.items():
                ips = [r["value"] for r in records]
                ret = cloud.del_record(domain, record_id)
                
                if ret.get("code") == 0 or "code" not in ret:
                    print(f"✓ 删除成功: {record_type} {records[0]['line']} - IPs: {ips}")
                else:
                    print(f"✗ 删除失败: {record_type} {records[0]['line']} - {ret.get('message', '未知错误')}")
        
        print(f"完成 {domain} - {sub_domain} 的运营商记录删除\n")
        
    except Exception as e:
        print(f"删除记录时出错: {e}")
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
    print("开始删除移动、联通、电信的所有A和AAAA记录")
    print("其他线路（境外、默认）保持不变")
    print("=" * 60)
    
    # 遍历所有域名和子域名
    for domain, sub_domains in DOMAINS.items():
        for sub_domain, lines in sub_domains.items():
            # 只处理配置了运营商线路的域名
            has_carrier = any(line in ["CM", "CU", "CT"] for line in lines)
            if has_carrier:
                delete_carrier_records(cloud, domain, sub_domain)
            else:
                print(f"跳过 {domain} - {sub_domain}（没有配置运营商线路）")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"程序执行失败: {e}")
        traceback.print_exc()
        sys.exit(1)