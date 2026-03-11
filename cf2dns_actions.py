#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, json, time, random, traceback
import ipaddress
import requests  # 使用 requests 调用 DoH API

# ==================== 从环境变量获取配置 ====================
config = json.loads(os.environ["CONFIG"])
# 格式: 
# {
#   "saas.itedev.com": {
#     "cn": 4,           # 生成A/AAAA记录
#     "cn1": 4           # 生成A/AAAA记录
#     # "def" 自动处理，通过DoH解析CNAME目标得到IP
#   }
# }
DOMAINS = json.loads(os.environ["DOMAINS"])

# CNAME 目标域名（需要解析出IP）
CNAME_TARGET = "fallback.itedev.com.cdn.cloudflare.net"

# Cloudflare DoH 端点
CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
# 备用 DoH 端点
CLOUDFLARE_DOH_BACKUP = "https://dns.cloudflare.com/dns-query"

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

# ==================== Cloudflare DoH 解析 ====================
def resolve_via_cloudflare_doh(domain, record_type='A'):
    """
    使用 Cloudflare DoH 解析域名
    record_type: A 或 AAAA
    返回IP列表
    """
    headers = {
        'Accept': 'application/dns-json',
        'User-Agent': 'cf2dns-updater/1.0'
    }
    
    params = {
        'name': domain,
        'type': record_type
    }
    
    # 尝试主 DoH 端点
    try:
        response = requests.get(CLOUDFLARE_DOH, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return parse_doh_response(data, record_type)
    except Exception as e:
        print(f"主DoH端点请求失败: {str(e)}")
    
    # 尝试备用 DoH 端点
    try:
        response = requests.get(CLOUDFLARE_DOH_BACKUP, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return parse_doh_response(data, record_type)
    except Exception as e:
        print(f"备用DoH端点请求失败: {str(e)}")
    
    return []

def parse_doh_response(data, record_type):
    """
    解析 DoH 响应，提取IP地址
    """
    ips = []
    
    # 检查是否有 Answer 部分
    if 'Answer' not in data:
        print(f"DoH响应中没有Answer部分: {data}")
        return ips
    
    for answer in data['Answer']:
        # 检查记录类型
        if record_type == 'A' and answer['type'] == 1:  # 1 是 A 记录
            ip = answer['data']
            if not is_ip_blacklisted(ip):
                ips.append(ip)
        elif record_type == 'AAAA' and answer['type'] == 28:  # 28 是 AAAA 记录
            ip = answer['data']
            if not is_ip_blacklisted(ip):
                ips.append(ip)
    
    return ips

def get_cname_target_ips():
    """
    通过 Cloudflare DoH 获取 CNAME 目标域名的所有IP地址
    返回 {'v4': [{'ip': ip}], 'v6': [{'ip': ip}]}
    """
    result = {'v4': [], 'v6': []}
    
    print(f"\n通过 Cloudflare DoH 解析: {CNAME_TARGET}")
    
    # 解析 A 记录 (IPv4)
    ipv4_list = resolve_via_cloudflare_doh(CNAME_TARGET, 'A')
    result['v4'] = [{'ip': ip} for ip in ipv4_list]
    print(f"  IPv4: 获取到 {len(ipv4_list)} 个IP")
    if ipv4_list:
        print(f"    {ipv4_list}")
    
    # 解析 AAAA 记录 (IPv6)
    ipv6_list = resolve_via_cloudflare_doh(CNAME_TARGET, 'AAAA')
    result['v6'] = [{'ip': ip} for ip in ipv6_list]
    print(f"  IPv6: 获取到 {len(ipv6_list)} 个IP")
    if ipv6_list:
        print(f"    {ipv6_list}")
    
    return result

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
                # IPv6地址空间太大，随机采样
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

# 获取 CNAME 目标的IP
CNAME_IPS = get_cname_target_ips()

def get_random_ips_from_pool(pool, count):
    """从IP池中随机获取指定数量的IP"""
    if not pool:
        return []
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

def get_record_sets(zone_id, full_domain):
    """获取指定域名的所有记录集"""
    request = ListRecordSetsWithLineRequest()
    request.limit = 100
    request.name = full_domain + "."
    
    response = client.list_record_sets_with_line(request)
    data = json.loads(str(response))
    
    records = []
    for record in data.get('recordsets', []):
        if record['name'] == full_domain + ".":
            records.append({
                'id': record['id'],
                'name': record['name'],
                'type': record['type'],
                'records': record.get('records', []),
                'line': record.get('line', ''),
                'ttl': record.get('ttl', 300)
            })
    return records

def create_record_set(zone_id, full_domain, record_type, ips, ttl=600):
    """创建记录集"""
    request = CreateRecordSetWithLineRequest()
    request.zone_id = zone_id
    
    request.body = CreateRecordSetWithLineReq(
        type=record_type,
        name=full_domain + ".",
        ttl=ttl,
        records=ips,
        line='default_view'
    )
    
    response = client.create_record_set_with_line(request)
    return json.loads(str(response))

def update_record_set(zone_id, record_id, full_domain, record_type, ips, ttl=600):
    """更新记录集"""
    request = UpdateRecordSetRequest()
    request.zone_id = zone_id
    request.recordset_id = record_id
    
    request.body = UpdateRecordSetReq(
        name=full_domain + ".",
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
    # 遍历所有主域名配置
    for main_domain, sub_configs in DOMAINS.items():
        # 获取主域名ID
        zone_id = get_zone_id(main_domain)
        if not zone_id:
            print(f"错误: 找不到主域名 {main_domain}")
            continue
        
        # 遍历每个子域名配置
        for sub_prefix, group_count in sub_configs.items():
            if group_count <= 0:
                print(f"跳过 {sub_prefix}.{main_domain}: 组数无效 {group_count}")
                continue
            
            # 构建完整的子域名
            full_sub_domain = f"{sub_prefix}.{main_domain}"
            
            print(f"\n处理域名: {full_sub_domain}")
            print(f"需要 {group_count} 组记录 (每组: 2个IPv4 + 2个IPv6)")
            
            # 判断是否是特殊的 def 子域名
            if sub_prefix == "def":
                print(f"  特殊处理: 使用 Cloudflare DoH 解析得到的IP")
                # 使用 CNAME 目标的IP
                ipv4_pool = [ip['ip'] for ip in CNAME_IPS['v4']]
                ipv6_pool = [ip['ip'] for ip in CNAME_IPS['v6']]
            else:
                # 使用随机IP池
                ipv4_pool = IPV4_POOL
                ipv6_pool = IPV6_POOL
            
            # 获取当前所有记录集
            existing_records = get_record_sets(zone_id, full_sub_domain)
            
            # 分离A和AAAA记录
            a_records = [r for r in existing_records if r['type'] == 'A' and r['line'] == 'default_view']
            aaaa_records = [r for r in existing_records if r['type'] == 'AAAA' and r['line'] == 'default_view']
            
            print(f"当前A记录数: {len(a_records)}")
            print(f"当前AAAA记录数: {len(aaaa_records)}")
            
            # 目标数量
            target_a_count = group_count
            target_aaaa_count = group_count
            
            # 处理A记录
            if target_a_count > 0:
                if not ipv4_pool:
                    print(f"  警告: IPv4池为空，跳过A记录")
                else:
                    # 从IPv4池中随机获取所有需要的IP
                    all_ipv4 = get_random_ips_from_pool(ipv4_pool, target_a_count * 2)
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
                                update_record_set(zone_id, a_records[i]['id'], full_sub_domain, 'A', ip_pair, config["ttl"])
                                print(f"  更新A记录[{i}]: {ip_pair}")
                            except Exception as e:
                                print(f"  更新A记录[{i}]失败: {str(e)}")
                        else:
                            # 创建新记录
                            try:
                                create_record_set(zone_id, full_sub_domain, 'A', ip_pair, config["ttl"])
                                print(f"  创建A记录[{i}]: {ip_pair}")
                            except Exception as e:
                                print(f"  创建A记录[{i}]失败: {str(e)}")
                    
                    # 删除多余的A记录
                    if len(a_records) > target_a_count:
                        for extra in a_records[target_a_count:]:
                            try:
                                delete_record_set(zone_id, extra['id'])
                                print(f"  删除多余A记录: {extra['id']} - {extra['records']}")
                            except Exception as e:
                                print(f"  删除A记录失败: {str(e)}")
            
            # 处理AAAA记录
            if target_aaaa_count > 0:
                if not ipv6_pool:
                    print(f"  警告: IPv6池为空，跳过AAAA记录")
                else:
                    # 从IPv6池中随机获取所有需要的IP
                    all_ipv6 = get_random_ips_from_pool(ipv6_pool, target_aaaa_count * 2)
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
                                update_record_set(zone_id, aaaa_records[i]['id'], full_sub_domain, 'AAAA', ip_pair, config["ttl"])
                                print(f"  更新AAAA记录[{i}]: {ip_pair}")
                            except Exception as e:
                                print(f"  更新AAAA记录[{i}]失败: {str(e)}")
                        else:
                            # 创建新记录
                            try:
                                create_record_set(zone_id, full_sub_domain, 'AAAA', ip_pair, config["ttl"])
                                print(f"  创建AAAA记录[{i}]: {ip_pair}")
                            except Exception as e:
                                print(f"  创建AAAA记录[{i}]失败: {str(e)}")
                    
                    # 删除多余的AAAA记录
                    if len(aaaa_records) > target_aaaa_count:
                        for extra in aaaa_records[target_aaaa_count:]:
                            try:
                                delete_record_set(zone_id, extra['id'])
                                print(f"  删除多余AAAA记录: {extra['id']} - {extra['records']}")
                            except Exception as e:
                                print(f"  删除AAAA记录失败: {str(e)}")
            
            print(f"完成 {full_sub_domain}")
    
    print("\n所有操作完成")
