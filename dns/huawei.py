#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author/Mail: tongdongdong@outlook.com
# Reference1: https://github.com/huaweicloud/huaweicloud-sdk-python-v3/tree/ff7df92d2a496871c7c2d84dfd2a7f4e2467fff5/huaweicloud-sdk-dns/huaweicloudsdkdns/v2/model 
# Reference2: https://support.huaweicloud.com/api-dns/dns_api_65003.html
# REGION: https://developer.huaweicloud.com/endpoint

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2 import *
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion
import json


class HuaWeiApi():
    def __init__(self, ACCESSID, SECRETKEY, REGION = 'cn-east-3'):
        self.AK = ACCESSID
        self.SK = SECRETKEY
        self.region = REGION
        self.client = DnsClient.new_builder() \
            .with_credentials(BasicCredentials(self.AK, self.SK)) \
            .with_region(DnsRegion.value_of(self.region)) \
            .build()
        self.zone_id = self.get_zones()

    def del_record(self, domain, record):
        """删除单条记录"""
        request = DeleteRecordSetsRequest()
        request.zone_id = self.zone_id[domain + '.']
        request.recordset_id = record
        response = self.client.delete_record_sets(request)
        result = json.loads(str(response))
        return result

    def get_record(self, domain, length, sub_domain, record_type):
        """获取记录列表（修正版-适配华为云实际返回格式）"""
        request = ListRecordSetsWithLineRequest()
        request.limit = length
        request.type = record_type
        if sub_domain == '@':
            request.name = domain + "."
        else:
            request.name = sub_domain + '.' + domain + "."
        
        response = self.client.list_record_sets_with_line(request)
        data = json.loads(str(response))
        
        result = {}
        records_temp = []
        
        # 调试：打印返回的数据结构
        # print(f"华为云API返回: {json.dumps(data, indent=2)}")
        
        for record in data.get('recordsets', []):
            # 检查是否匹配当前子域名
            record_name = record.get('name', '')
            expected_name = (domain + '.') if sub_domain == '@' else (sub_domain + '.' + domain + '.')
            
            if record_name == expected_name and record.get('type') == record_type:
                # 转换线路格式
                record['line'] = self.line_format(record.get('line', 'default_view'))
                
                # 华为云的记录值在 'records' 字段中，是一个列表
                # 我们需要为每个IP创建一条记录（保持与原逻辑兼容）
                records_list = record.get('records', [])
                
                # 如果这个记录集有多个IP，为每个IP创建一个记录项
                for ip in records_list:
                    record_item = {
                        'id': record.get('id'),
                        'line': record['line'],
                        'value': ip,  # 使用单个IP作为value
                        'type': record.get('type'),
                        'ttl': record.get('ttl'),
                        'name': record.get('name')
                    }
                    records_temp.append(record_item)
        
        result['data'] = {'records': records_temp}
        result['code'] = 0
        return result

    def create_record(self, domain, sub_domain, values, record_type, line, ttl):
        """
        创建记录集（增强版-支持批量IP）
        :param values: 可以是单个IP字符串，也可以是IP字符串列表
        """
        request = CreateRecordSetWithLineRequest()
        request.zone_id = self.zone_id[domain + '.']
        if sub_domain == '@':
            name = domain + "."
        else:
            name = sub_domain + '.' + domain + "."
        
        # 确保values总是列表
        if isinstance(values, str):
            records_list = [values]
        else:
            records_list = values
        
        request.body = CreateRecordSetWithLineReq(
            type=record_type,
            name=name,
            ttl=ttl,
            records=records_list,  # 直接传入IP列表
            line=self.line_format(line)
        )
        response = self.client.create_record_set_with_line(request)
        result = json.loads(str(response))
        return result
        
    def change_record(self, domain, record_id, sub_domain, values, record_type, line, ttl):
        """
        修改记录集（增强版-支持批量IP）
        :param values: 可以是单个IP字符串，也可以是IP字符串列表
        """
        request = UpdateRecordSetRequest()
        request.zone_id = self.zone_id[domain + '.']
        request.recordset_id = record_id
        if sub_domain == '@':
            name = domain + "."
        else:
            name = sub_domain + '.' + domain + "."
        
        # 确保values总是列表
        if isinstance(values, str):
            records_list = [values]
        else:
            records_list = values
        
        request.body = UpdateRecordSetReq(
            name=name,
            type=record_type,
            ttl=ttl,
            records=records_list  # 直接传入IP列表
        )
        response = self.client.update_record_set(request)
        result = json.loads(str(response))
        return result

    def get_zones(self):
        """获取域名zone_id"""
        request = ListPublicZonesRequest()
        response = self.client.list_public_zones(request)
        result = json.loads(str(response))
        zone_id = {}
        for zone in result.get('zones', []):
            zone_id[zone['name']] = zone['id'] 
        return zone_id

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


if __name__ == '__main__':
    # 测试代码
    hw_api = HuaWeiApi('YOUR_ACCESS_KEY', 'YOUR_SECRET_KEY')
    # 测试获取记录
    result = hw_api.get_record('example.com', 100, '@', 'A')
    print(json.dumps(result, indent=2, ensure_ascii=False))