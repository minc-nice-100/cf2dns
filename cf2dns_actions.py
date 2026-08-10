#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os, json, time, random, traceback
import ipaddress
import requests

# ==================== 从环境变量获取配置 ====================
config = json.loads(os.environ["CONFIG"])
# 格式: 
# {
#   "saas.itedev.com": {
#     "cn": 4,           # 生成A/AAAA记录，每组2个IP
#     "cn1": 4,
#     "@": 2,
#     "def": 2,          # 使用DoH解析得到的IP池分组
#     "test": 0          # 新增：0表示全部IP写入一条记录（DoH模式）
#   }
# }
DOMAINS = json.loads(os.environ["DOMAINS"])

# CNAME 目标域名（需要解析出IP）
CNAME_TARGET = "fallback.itedev.com.cdn.cloudflare.net"

# Cloudflare DoH 端点
CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query"
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
    
    if 'Answer' not in data:
        print(f"DoH响应中没有Answer部分: {data}")
        return ips
    
    for answer in data['Answer']:
        if record_type == 'A' and answer['type'] == 1:      # A 记录
            ip = answer['data']
            if not is_ip_blacklisted(ip):
                ips.append(ip)
        elif record_type == 'AAAA' and answer['type'] == 28: # AAAA 记录
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
    
    ipv4_list = resolve_via_cloudflare_doh(CNAME_TARGET, 'A')
    result['v4'] = [{'ip': ip} for ip in ipv4_list]
    print(f"  IPv4: 获取到 {len(ipv4_list)} 个IP")
    if ipv4_list:
        print(f"    {ipv4_list}")
    
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
                hosts = list(network.hosts())
                for ip in hosts:
                    ip_str = str(ip)
                    if not is_ip_blacklisted(ip_str):
                        ip_pool.append(ip_str)
            else:
                # IPv6: 排除网络地址，随机采样
                if network.num_addresses <= 1:
                    continue
                first = int(network.network_address)
                last = int(network.broadcast_address) if network.broadcast_address else first + network.num_addresses - 1
                
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

# 判断是否需要提前解析 DoH（存在值为0的子域名 或 存在def子域名）
need_doh = any(
    any(v == 0 for v in sub_configs.values()) or 'def' in sub_configs
    for sub_configs in DOMAINS.values()
)
if need_doh:
    CNAME_IPS = get_cname_target_ips()
else:
    CNAME_IPS = {'v4': [], 'v6': []}
    print("\n没有需要DoH解析的域名，跳过 DoH 解析")

def get_random_ips_from_pool(pool, count):
    """从IP池中随机获取指定数量的IP"""
    if not pool:
        return []
    if len(pool) < count:
        print(f"警告: IP池只有 {len(pool)} 个IP，但需要 {count} 个")
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
    """
    获取指定域名的所有记录集（带分页，兼容名称末尾点）
    """
    all_records = []
    offset = 0
    limit = 100
    query_name = full_domain.rstrip('.') + '.'

    while True:
        request = ListRecordSetsWithLineRequest()
        request.zone_id = zone_id
        request.limit = limit
        request.offset = offset
        request.name = query_name

        response = client.list_record_sets_with_line(request)
        data = json.loads(str(response))
        recordsets = data.get('recordsets', [])

        for record in recordsets:
            if record['name'].rstrip('.') == full_domain.rstrip('.'):
                all_records.append({
                    'id': record['id'],
                    'name': record['name'],
                    'type': record['type'],
                    'records': record.get('records', []),
                    'line': record.get('line', ''),
                    'ttl': record.get('ttl', 300)
                })

        if len(recordsets) < limit:
            break
        offset += limit

    return all_records

def create_record_set(zone_id, full_domain, record_type, ips, ttl=600):
    """创建记录集"""
    request = CreateRecordSetWithLineRequest()
    request.zone_id = zone_id
    
    request.body = CreateRecordSetWithLineReq(
        type=record_type,
        name=full_domain.rstrip('.') + ".",
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
        name=full_domain.rstrip('.') + ".",
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
    default_ttl = config.get("ttl", 600)

    for main_domain, sub_configs in DOMAINS.items():
        zone_id = get_zone_id(main_domain)
        if not zone_id:
            print(f"错误: 找不到主域名 {main_domain}")
            continue
        
        for sub_prefix, group_count in sub_configs.items():
            # 构建完整子域名
            if sub_prefix == "@":
                full_sub_domain = main_domain
                display_name = main_domain
            else:
                full_sub_domain = f"{sub_prefix}.{main_domain}"
                display_name = full_sub_domain

            print(f"\n处理域名: {display_name} (配置值: {group_count})")

            # ---------- 特殊处理：group_count == 0 表示 DoH 模式（全部IP写入一条记录） ----------
            if group_count == 0:
                print(f"  DoH模式: 将解析到的全部IP写入一条A记录和一条AAAA记录")
                existing_records = get_record_sets(zone_id, full_sub_domain)
                a_records = [r for r in existing_records if r['type'] == 'A' and r['line'] == 'default_view']
                aaaa_records = [r for r in existing_records if r['type'] == 'AAAA' and r['line'] == 'default_view']

                ipv4_list = [ip['ip'] for ip in CNAME_IPS['v4']]
                ipv6_list = [ip['ip'] for ip in CNAME_IPS['v6']]

                # 处理 A 记录
                if ipv4_list:
                    if a_records:
                        update_record_set(zone_id, a_records[0]['id'], full_sub_domain, 'A', ipv4_list, default_ttl)
                        print(f"  更新A记录: {ipv4_list}")
                        for extra in a_records[1:]:
                            delete_record_set(zone_id, extra['id'])
                            print(f"  删除多余A记录: {extra['id']}")
                    else:
                        create_record_set(zone_id, full_sub_domain, 'A', ipv4_list, default_ttl)
                        print(f"  创建A记录: {ipv4_list}")
                else:
                    for rec in a_records:
                        delete_record_set(zone_id, rec['id'])
                        print(f"  删除A记录: {rec['id']}")

                # 处理 AAAA 记录
                if ipv6_list:
                    if aaaa_records:
                        update_record_set(zone_id, aaaa_records[0]['id'], full_sub_domain, 'AAAA', ipv6_list, default_ttl)
                        print(f"  更新AAAA记录: {ipv6_list}")
                        for extra in aaaa_records[1:]:
                            delete_record_set(zone_id, extra['id'])
                            print(f"  删除多余AAAA记录: {extra['id']}")
                    else:
                        create_record_set(zone_id, full_sub_domain, 'AAAA', ipv6_list, default_ttl)
                        print(f"  创建AAAA记录: {ipv6_list}")
                else:
                    for rec in aaaa_records:
                        delete_record_set(zone_id, rec['id'])
                        print(f"  删除AAAA记录: {rec['id']}")

                continue  # 跳过后续分组逻辑

            # ---------- 正常分组模式（group_count > 0） ----------
            # 确定IP池来源
            if sub_prefix == "def":
                # def 特殊处理：使用 DoH 解析的 IP 池
                ipv4_pool = [ip['ip'] for ip in CNAME_IPS['v4']]
                ipv6_pool = [ip['ip'] for ip in CNAME_IPS['v6']]
                print(f"  使用 DoH 解析得到的IP池 (IPv4: {len(ipv4_pool)}, IPv6: {len(ipv6_pool)})")
            else:
                ipv4_pool = IPV4_POOL
                ipv6_pool = IPV6_POOL

            print(f"需要 {group_count} 组记录 (每组: 2个IPv4 + 2个IPv6)")

            # 获取当前记录集
            existing_records = get_record_sets(zone_id, full_sub_domain)
            a_records = [r for r in existing_records if r['type'] == 'A' and r['line'] == 'default_view']
            aaaa_records = [r for r in existing_records if r['type'] == 'AAAA' and r['line'] == 'default_view']

            print(f"当前A记录数: {len(a_records)}")
            print(f"当前AAAA记录数: {len(aaaa_records)}")

            target_count = group_count

            # 处理A记录
            if target_count > 0 and ipv4_pool:
                all_ipv4 = get_random_ips_from_pool(ipv4_pool, target_count * 2)
                print(f"获取到 {len(all_ipv4)} 个IPv4地址")
                for i in range(target_count):
                    start_idx = i * 2
                    if start_idx + 1 >= len(all_ipv4):
                        print(f"  警告: IPv4地址不足，跳过第 {i} 组")
                        break
                    ip_pair = all_ipv4[start_idx:start_idx + 2]
                    if i < len(a_records):
                        update_record_set(zone_id, a_records[i]['id'], full_sub_domain, 'A', ip_pair, default_ttl)
                        print(f"  更新A记录[{i}]: {ip_pair}")
                    else:
                        create_record_set(zone_id, full_sub_domain, 'A', ip_pair, default_ttl)
                        print(f"  创建A记录[{i}]: {ip_pair}")
                # 删除多余记录
                if len(a_records) > target_count:
                    for extra in a_records[target_count:]:
                        delete_record_set(zone_id, extra['id'])
                        print(f"  删除多余A记录: {extra['id']} - {extra['records']}")
            else:
                # 如果目标为0或IP池为空，删除所有A记录
                for rec in a_records:
                    delete_record_set(zone_id, rec['id'])
                    print(f"  删除A记录: {rec['id']} (目标数量0或IP池为空)")

            # 处理AAAA记录
            if target_count > 0 and ipv6_pool:
                all_ipv6 = get_random_ips_from_pool(ipv6_pool, target_count * 2)
                print(f"获取到 {len(all_ipv6)} 个IPv6地址")
                for i in range(target_count):
                    start_idx = i * 2
                    if start_idx + 1 >= len(all_ipv6):
                        print(f"  警告: IPv6地址不足，跳过第 {i} 组")
                        break
                    ip_pair = all_ipv6[start_idx:start_idx + 2]
                    if i < len(aaaa_records):
                        update_record_set(zone_id, aaaa_records[i]['id'], full_sub_domain, 'AAAA', ip_pair, default_ttl)
                        print(f"  更新AAAA记录[{i}]: {ip_pair}")
                    else:
                        create_record_set(zone_id, full_sub_domain, 'AAAA', ip_pair, default_ttl)
                        print(f"  创建AAAA记录[{i}]: {ip_pair}")
                if len(aaaa_records) > target_count:
                    for extra in aaaa_records[target_count:]:
                        delete_record_set(zone_id, extra['id'])
                        print(f"  删除多余AAAA记录: {extra['id']} - {extra['records']}")
            else:
                for rec in aaaa_records:
                    delete_record_set(zone_id, rec['id'])
                    print(f"  删除AAAA记录: {rec['id']} (目标数量0或IP池为空)")

            print(f"完成 {display_name}")

    print("\n所有操作完成")
