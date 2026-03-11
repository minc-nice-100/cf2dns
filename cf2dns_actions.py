#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, json, time, random, traceback
import ipaddress

# ==================== 从环境变量获取配置 ====================
config = json.loads(os.environ["CONFIG"])
# 格式: {"saas.itedev.com": {"cn": 33}}  # cn是组数，33表示33组
DOMAINS = json.loads(os.environ["DOMAINS"])

# ==================== 从环境变量获取CIDR配置 ====================
def get_cidrs_from_env(env_var_name):
    cidr_str = os.environ.get(env_var_name, "")
    if not cidr_str:
        return []
    cidrs = []
    for line in cidr_str.split('\n'):
        for cidr in line.split(','):
            cidr = cidr.strip()
            if cidr and not cidr.startswith('#'):
                cidrs.append(cidr)
    return cidrs

IPV4_CIDRS = get_cidrs_from_env("IPV4_CIDRS")
IPV6_CIDRS = get_cidrs_from_env("IPV6_CIDRS")

# ==================== IP黑名单配置 ====================
CUSTOM_BLACKLIST = get_cidrs_from_env("CUSTOM_BLACKLIST")

IP_BLACKLIST_CIDR = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "0.0.0.0/8", "100.64.0.0/10",
    "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]

if CUSTOM_BLACKLIST:
    IP_BLACKLIST_CIDR.extend(CUSTOM_BLACKLIST)

IP_BLACKLIST_NETWORKS = []
for cidr in IP_BLACKLIST_CIDR:
    try:
        IP_BLACKLIST_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
    except:
        pass

def is_ip_blacklisted(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
        for network in IP_BLACKLIST_NETWORKS:
            if ip_addr in network:
                return True
        return False
    except:
        return False

# ==================== 拍平CIDR ====================
def flatten_cidrs(cidr_list, is_v6=False):
    """
    将CIDR列表拍平，生成所有可能的IP地址池
    返回一个IP地址列表
    """
    ip_pool = []
    
    for cidr in cidr_list:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            if network.version == 4:
                # IPv4: 排除网络地址和广播地址
                if network.num_addresses <= 2:
                    continue
                # 获取所有可用主机IP
                hosts = list(network.hosts())
                for ip in hosts:
                    ip_str = str(ip)
                    if not is_ip_blacklisted(ip_str):
                        ip_pool.append(ip_str)
            else:
                # IPv6: 排除网络地址
                if network.num_addresses <= 1:
                    continue
                # IPv6地址空间太大，不能全部展开，随机采样
                # 这里我们生成一个范围内的随机IP
                first = int(network.network_address)
                last = int(network.broadcast_address) if network.broadcast_address else first + network.num_addresses - 1
                
                # 采样数量：最多1000个随机IP
                sample_size = min(1000, network.num_addresses)
                for _ in range(sample_size):
                    random_int = random.randint(first + 1, last)
                    ip = ipaddress.ip_address(random_int)
                    ip_str = str(ip)
                    if not is_ip_blacklisted(ip_str):
                        ip_pool.append(ip_str)
                
        except Exception as e:
            print(f"处理CIDR {cidr} 时出错: {str(e)}")
            continue
    
    # 去重
    ip_pool = list(set(ip_pool))
    print(f"IPv{'6' if is_v6 else '4'} IP池大小: {len(ip_pool)}")
    return ip_pool

# 初始化IP池
print("正在初始化IP池...")
IPV4_POOL = flatten_cidrs(IPV4_CIDRS, is_v6=False)
IPV6_POOL = flatten_cidrs(IPV6_CIDRS, is_v6=True)
print(f"IPv4池: {len(IPV4_POOL)} 个可用IP")
print(f"IPv6池: {len(IPV6_POOL)} 个可用IP")

def get_random_ips_from_pool(pool, count):
    """从IP池中随机获取指定数量的IP"""
    if len(pool) < count:
        print(f"警告: IP池只有 {len(pool)} 个IP，但需要 {count} 个")
        # 允许重复使用IP
        return random.choices(pool, k=count)
    return random.sample(pool, count)

# ==================== 华为云API ====================
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkdns.v2 import *
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion

# 初始化客户端
credentials = BasicCredentials(config["secretid"], config["secretkey"])
client = DnsClient.new_builder() \
    .with_credentials(credentials) \
    .with_region(DnsRegion.value_of(config["region_hw"])) \
    .build()

def get_zone_id(domain):
    """获取域名ID"""
    request = ListPublicZonesRequest()
    response = client.list_public_zones(request)
    result = json.loads(str(response))
    for zone in result['zones']:
        if zone['name'] == domain + '.':
            return zone['id']
    return None

def get_record_sets(zone_id, sub_domain, domain):
    """获取指定子域名的所有记录集"""
    request = ListRecordSetsWithLineRequest()
    request.limit = 100
    
    if sub_domain == '@':
        request.name = domain + "."
    else:
        request.name = sub_domain + '.' + domain + "."
    
    response = client.list_record_sets_with_line(request)
    data = json.loads(str(response))
    
    records = []
    for record in data.get('recordsets', []):
        records.append({
            'id': record['id'],
            'name': record['name'],
            'type': record['type'],
            'records': record.get('records', []),
            'line': record.get('line', ''),
            'ttl': record.get('ttl', 300)
        })
    return records

def create_record_set(zone_id, sub_domain, domain, record_type, ips, ttl=600):
    """创建记录集"""
    request = CreateRecordSetWithLineRequest()
    request.zone_id = zone_id
    
    if sub_domain == '@':
        name = domain + "."
    else:
        name = sub_domain + '.' + domain + "."
    
    request.body = CreateRecordSetWithLineReq(
        type=record_type,
        name=name,
        ttl=ttl,
        records=ips,
        line='default_view'  # 全部使用默认线路
    )
    
    response = client.create_record_set_with_line(request)
    return json.loads(str(response))

def update_record_set(zone_id, record_id, sub_domain, domain, record_type, ips, ttl=600):
    """更新记录集"""
    request = UpdateRecordSetRequest()
    request.zone_id = zone_id
    request.recordset_id = record_id
    
    if sub_domain == '@':
        name = domain + "."
    else:
        name = sub_domain + '.' + domain + "."
    
    request.body = UpdateRecordSetReq(
        name=name,
        type=record_type,
        ttl=ttl,
        records=ips
    )
    
    response = client.update_record_set(request)
    return json.loads(str(response))

def delete_record_set(zone_id, record_id):
    """删除记录集"""
    request = DeleteRecordSetsRequest()
    request.zone_id = zone_id
    request.recordset_id = record_id
    response = client.delete_record_sets(request)
    return json.loads(str(response))

# ==================== 主逻辑 ====================
if __name__ == '__main__':
    # 检查IP池
    if not IPV4_POOL:
        print("错误: IPv4池为空")
        sys.exit(1)
    if not IPV6_POOL:
        print("错误: IPv6池为空")
        sys.exit(1)
    
    # 遍历所有域名
    for domain, configs in DOMAINS.items():
        # 获取组数
        group_count = configs.get("cn", 0)
        if group_count <= 0:
            print(f"跳过 {domain}: 组数无效 {group_count}")
            continue
        
        print(f"\n处理域名: {domain}")
        print(f"需要 {group_count} 组记录 (每组: 2个IPv4 + 2个IPv6)")
        
        # 获取域名ID
        zone_id = get_zone_id(domain)
        if not zone_id:
            print(f"错误: 找不到域名 {domain}")
            continue
        
        # 处理每个子域名
        for sub_domain in ['@']:  # 这里可以扩展，目前只处理主域名
            print(f"\n子域名: {sub_domain}")
            
            # 获取当前所有记录集
            existing_records = get_record_sets(zone_id, sub_domain, domain)
            
            # 分离A和AAAA记录（只处理默认线路）
            a_records = [r for r in existing_records if r['type'] == 'A' and r['line'] == 'default_view']
            aaaa_records = [r for r in existing_records if r['type'] == 'AAAA' and r['line'] == 'default_view']
            
            print(f"当前A记录数: {len(a_records)}")
            print(f"当前AAAA记录数: {len(aaaa_records)}")
            
            # 目标数量
            target_a_count = group_count
            target_aaaa_count = group_count
            
            # 处理A记录
            if target_a_count > 0:
                # 从IPv4池中随机获取所有需要的IP
                all_ipv4 = get_random_ips_from_pool(IPV4_POOL, target_a_count * 2)
                print(f"获取到 {len(all_ipv4)} 个IPv4地址")
                
                # 更新或创建A记录
                for i in range(target_a_count):
                    # 每2个IP为一组
                    start_idx = i * 2
                    if start_idx + 1 >= len(all_ipv4):
                        break
                    
                    ip_pair = all_ipv4[start_idx:start_idx + 2]
                    
                    if i < len(a_records):
                        # 更新现有记录
                        try:
                            update_record_set(zone_id, a_records[i]['id'], sub_domain, domain, 'A', ip_pair, config["ttl"])
                            print(f"更新A记录[{i}]: {ip_pair}")
                        except Exception as e:
                            print(f"更新A记录[{i}]失败: {str(e)}")
                    else:
                        # 创建新记录
                        try:
                            create_record_set(zone_id, sub_domain, domain, 'A', ip_pair, config["ttl"])
                            print(f"创建A记录[{i}]: {ip_pair}")
                        except Exception as e:
                            print(f"创建A记录[{i}]失败: {str(e)}")
                
                # 删除多余的A记录
                if len(a_records) > target_a_count:
                    for extra in a_records[target_a_count:]:
                        try:
                            delete_record_set(zone_id, extra['id'])
                            print(f"删除多余A记录: {extra['id']} - {extra['records']}")
                        except Exception as e:
                            print(f"删除A记录失败: {str(e)}")
            
            # 处理AAAA记录
            if target_aaaa_count > 0:
                # 从IPv6池中随机获取所有需要的IP
                all_ipv6 = get_random_ips_from_pool(IPV6_POOL, target_aaaa_count * 2)
                print(f"获取到 {len(all_ipv6)} 个IPv6地址")
                
                # 更新或创建AAAA记录
                for i in range(target_aaaa_count):
                    # 每2个IP为一组
                    start_idx = i * 2
                    if start_idx + 1 >= len(all_ipv6):
                        break
                    
                    ip_pair = all_ipv6[start_idx:start_idx + 2]
                    
                    if i < len(aaaa_records):
                        # 更新现有记录
                        try:
                            update_record_set(zone_id, aaaa_records[i]['id'], sub_domain, domain, 'AAAA', ip_pair, config["ttl"])
                            print(f"更新AAAA记录[{i}]: {ip_pair}")
                        except Exception as e:
                            print(f"更新AAAA记录[{i}]失败: {str(e)}")
                    else:
                        # 创建新记录
                        try:
                            create_record_set(zone_id, sub_domain, domain, 'AAAA', ip_pair, config["ttl"])
                            print(f"创建AAAA记录[{i}]: {ip_pair}")
                        except Exception as e:
                            print(f"创建AAAA记录[{i}]失败: {str(e)}")
                
                # 删除多余的AAAA记录
                if len(aaaa_records) > target_aaaa_count:
                    for extra in aaaa_records[target_aaaa_count:]:
                        try:
                            delete_record_set(zone_id, extra['id'])
                            print(f"删除多余AAAA记录: {extra['id']} - {extra['records']}")
                        except Exception as e:
                            print(f"删除AAAA记录失败: {str(e)}")
            
            print(f"完成 {sub_domain}.{domain}")
    
    print("\n所有操作完成")
