#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com

import sys, os, json, requests, time, base64, shutil, random, traceback

from dns.huawei import HuaWeiApi

config = json.loads(os.environ["CONFIG"])
#CM:移动 CU:联通 CT:电信  AB:境外 DEF:默认
#修改需要更改的dnspod域名和子域名
DOMAINS = json.loads(os.environ["DOMAINS"])
#获取服务商信息
provider_data = json.loads(os.environ["PROVIDER"])

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
            print(f"API返回数据: {json.dumps(result, ensure_ascii=False)[:500]}...")
            return result
        else:
            print(f"获取优选IP失败: HTTP状态码 {response.status_code}")
            print(f"响应内容: {response.text[:200]}")
            return None
    except Exception as e:
        print(f"获取优选IP异常: {str(e)}")
        traceback.print_exc()
        return None

def extract_ips_from_api_response(api_response, line_type):
    """
    从API响应中提取指定线路的IP列表
    适配新API格式: response.success.data.v4.CM[].ip
    """
    try:
        if not api_response or not api_response.get("success"):
            print(f"API响应未返回成功状态: {api_response}")
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
        
        # 根据线路类型获取IP列表
        line_mapping = {
            "CM": "CM",  # 移动
            "CU": "CU",  # 联通
            "CT": "CT",  # 电信
            "AB": "CT",  # 境外默认使用电信线路
            "DEF": "CT"  # 默认使用电信线路
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
                ip_list.append({
                    "ip": item["ip"],
                    "colo": item.get("colo", ""),
                    "speed": item.get("speed", 0),
                    "latency": item.get("latency", 0)
                })
        
        print(f"线路 {line_type} 提取到 {len(ip_list)} 个IP")
        return ip_list
        
    except Exception as e:
        print(f"提取IP列表异常: {str(e)}")
        traceback.print_exc()
        return []

def update_huawei_dns(cloud, domain, sub_domain, record_type, line, existing_records, new_ips, ttl):
    """
    为华为云批量更新DNS记录 - 取消5条限制，支持任意数量
    """
    try:
        # 提取现有IP列表
        existing_ips = [record["value"] for record in existing_records]
        new_ip_values = [ip_info["ip"] for ip_info in new_ips]
        
        # 需要新增的IP (在新列表中但不在现有列表中)
        ips_to_add = [ip for ip in new_ip_values if ip not in existing_ips]
        
        # 需要删除的记录 (在现有列表中但不在新列表中)
        records_to_remove = [record for record in existing_records if record["value"] not in new_ip_values]
        
        # 需要保留的记录 (同时在两个列表中)
        records_to_keep = [record for record in existing_records if record["value"] in new_ip_values]
        
        print(f"域名: {domain} 子域名: {sub_domain} 线路: {line}")
        print(f"现有IP数量: {len(existing_ips)}, 目标IP数量: {len(new_ip_values)}")
        print(f"需要新增: {len(ips_to_add)}个, 需要删除: {len(records_to_remove)}个, 需要保留: {len(records_to_keep)}个")
        
        if ips_to_add:
            print(f"新增IP: {ips_to_add}")
        if records_to_remove:
            print(f"删除IP: {[r['value'] for r in records_to_remove]}")
        
        # 删除不需要的记录
        for record in records_to_remove:
            try:
                ret = cloud.del_record(domain, record["recordId"])
                if ret and ret.get("code") == 0:
                    print(f"✓ 删除DNS成功: {time.strftime('%Y-%m-%d %H:%M:%S')} "
                          f"域名: {domain} 子域名: {sub_domain} 线路: {line} "
                          f"值: {record['value']}")
                else:
                    print(f"✗ 删除DNS失败: {time.strftime('%Y-%m-%d %H:%M:%S')} "
                          f"域名: {domain} 子域名: {sub_domain} 线路: {line} "
                          f"值: {record['value']} 错误: {ret.get('message', '未知错误') if ret else '无返回'}")
            except Exception as e:
                print(f"✗ 删除DNS异常: {str(e)}")
        
        # 创建新记录
        for ip_info in new_ips:
            ip = ip_info["ip"]
            if ip in ips_to_add:  # 只创建新增的IP
                try:
                    ret = cloud.create_record(domain, sub_domain, ip, record_type, line, ttl)
                    if ret and ret.get("code") == 0:
                        print(f"✓ 创建DNS成功: {time.strftime('%Y-%m-%d %H:%M:%S')} "
                              f"域名: {domain} 子域名: {sub_domain} 线路: {line} 值: {ip} "
                              f"[{ip_info.get('colo', 'N/A')} {ip_info.get('speed', 0)}Mbps]")
                    else:
                        print(f"✗ 创建DNS失败: {time.strftime('%Y-%m-%d %H:%M:%S')} "
                              f"域名: {domain} 子域名: {sub_domain} 线路: {line} 值: {ip} "
                              f"错误: {ret.get('message', '未知错误') if ret else '无返回'}")
                except Exception as e:
                    print(f"✗ 创建DNS异常: {str(e)}")
        
        final_count = len(records_to_keep) + len(ips_to_add)
        print(f"✓ 域名 {domain} 子域名 {sub_domain} 线路 {line} 更新完成，当前记录数: {final_count}")
        
    except Exception as e:
        print(f"✗ 批量更新DNS异常: {time.strftime('%Y-%m-%d %H:%M:%S')} 错误: {str(e)}")
        traceback.print_exc()

def changeDNS(line, s_info, c_info, domain, sub_domain, cloud):
    """修改DNS记录 - 华为云专用版本"""
    global config
    
    # 确定记录类型
    if iptype == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"

    # 线路名称映射
    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line_chinese = lines[line]
    
    print(f"处理线路: {line} -> {line_chinese}, 获取到 {len(c_info)} 个优选IP")
    
    # 调用华为云批量更新函数
    update_huawei_dns(cloud, domain, sub_domain, recordType, line_chinese, 
                     s_info, c_info, config["ttl"])

def main(cloud):
    """主函数"""
    global config
    if iptype == 'v6':
        recordType = "AAAA"
        print("处理IPv6记录")
    else:
        recordType = "A"
        print("处理IPv4记录")
    
    if len(DOMAINS) > 0:
        try:
            # 获取优选IP
            api_response = get_optimization_ip()
            if api_response is None:
                print(f"获取优选IP失败: API返回空")
                return
            
            # 检查API返回格式
            if not api_response.get("success"):
                print(f"API返回错误: {api_response}")
                return
            
            # 提取各线路IP
            cf_cmips = extract_ips_from_api_response(api_response, "CM")
            cf_cuips = extract_ips_from_api_response(api_response, "CU")
            cf_ctips = extract_ips_from_api_response(api_response, "CT")
            
            print(f"\n=== IP统计 ===")
            print(f"移动(CM)线路: {len(cf_cmips)} 个IP")
            print(f"联通(CU)线路: {len(cf_cuips)} 个IP")
            print(f"电信(CT)线路: {len(cf_ctips)} 个IP")
            
            if cf_cmips:
                print(f"移动示例: {cf_cmips[0]['ip']} ({cf_cmips[0].get('colo', 'N/A')})")
            if cf_cuips:
                print(f"联通示例: {cf_cuips[0]['ip']} ({cf_cuips[0].get('colo', 'N/A')})")
            if cf_ctips:
                print(f"电信示例: {cf_ctips[0]['ip']} ({cf_ctips[0].get('colo', 'N/A')})")
            print("="*40)
            
            for domain, sub_domains in DOMAINS.items():
                print(f"\n处理域名: {domain}")
                for sub_domain, lines in sub_domains.items():
                    print(f"  子域名: {sub_domain}, 线路: {lines}")
                    
                    # 复制IP列表，避免修改原始数据
                    temp_cf_cmips = cf_cmips.copy() if cf_cmips else []
                    temp_cf_cuips = cf_cuips.copy() if cf_cuips else []
                    temp_cf_ctips = cf_ctips.copy() if cf_ctips else []
                    temp_cf_abips = cf_ctips.copy() if cf_ctips else []  # 境外使用电信IP
                    temp_cf_defips = cf_ctips.copy() if cf_ctips else []  # 默认使用电信IP
                    
                    # 获取现有记录
                    try:
                        ret = cloud.get_record(domain, 1000, sub_domain, recordType)  # 设置较大数量以获取所有记录
                        
                        if ret.get("code") != 0:
                            print(f"  获取DNS记录失败: {domain} {sub_domain} {ret}")
                            continue
                        
                        # 按线路分类现有记录
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        ab_info = []
                        def_info = []
                        
                        records = ret.get("data", {}).get("records", [])
                        print(f"  现有记录总数: {len(records)}条")
                        
                        for record in records:
                            info = {}
                            info["recordId"] = record.get("id", record.get("recordId"))
                            info["value"] = record.get("value")
                            
                            record_line = record.get("line")
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
                        
                        print(f"    移动记录: {len(cm_info)}条, 联通: {len(cu_info)}条, 电信: {len(ct_info)}条, "
                              f"境外: {len(ab_info)}条, 默认: {len(def_info)}条")
                        
                        # 处理每个线路
                        for line in lines:
                            print(f"\n  处理线路: {line}")
                            if line == "CM":
                                if temp_cf_cmips:
                                    changeDNS("CM", cm_info, temp_cf_cmips, domain, sub_domain, cloud)
                                else:
                                    print(f"    线路 CM 无可用IP，跳过")
                            elif line == "CU":
                                if temp_cf_cuips:
                                    changeDNS("CU", cu_info, temp_cf_cuips, domain, sub_domain, cloud)
                                else:
                                    print(f"    线路 CU 无可用IP，跳过")
                            elif line == "CT":
                                if temp_cf_ctips:
                                    changeDNS("CT", ct_info, temp_cf_ctips, domain, sub_domain, cloud)
                                else:
                                    print(f"    线路 CT 无可用IP，跳过")
                            elif line == "AB":
                                if temp_cf_abips:
                                    changeDNS("AB", ab_info, temp_cf_abips, domain, sub_domain, cloud)
                                else:
                                    print(f"    线路 AB 无可用IP，跳过")
                            elif line == "DEF":
                                if temp_cf_defips:
                                    changeDNS("DEF", def_info, temp_cf_defips, domain, sub_domain, cloud)
                                else:
                                    print(f"    线路 DEF 无可用IP，跳过")
                                
                    except Exception as e:
                        print(f"  处理域名 {domain} 子域名 {sub_domain} 时出错: {str(e)}")
                        traceback.print_exc()
                        
        except Exception as e:
            print(f"主函数执行异常: {str(e)}")
            traceback.print_exc()

if __name__ == '__main__':
    # 检查配置
    print("="*60)
    print(f"脚本启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"DNS服务商: 华为云 (ID: {config.get('dns_server')})")
    print(f"IPv4启用: {config.get('ipv4')}")
    print(f"IPv6启用: {config.get('ipv6')}")
    print(f"TTL: {config.get('ttl')}")
    print(f"数据源: {config.get('data_server')}")
    print("="*60)
    
    # 初始化华为云客户端
    if config["dns_server"] == 3:
        try:
            cloud = HuaWeiApi(config["secretid"], config["secretkey"], config["region_hw"])
            print("✓ 华为云客户端初始化成功")
        except Exception as e:
            print(f"✗ 华为云客户端初始化失败: {str(e)}")
            sys.exit(1)
    else:
        print(f"✗ 错误: 当前DNS服务商ID为 {config['dns_server']}，但本脚本仅支持华为云(ID=3)")
        sys.exit(1)
    
    # 处理IPv4
    if config.get("ipv4") == "on":
        iptype = "v4"
        print("\n" + "="*40)
        print("开始处理IPv4记录")
        print("="*40)
        main(cloud)
    
    # 处理IPv6
    if config.get("ipv6") == "on":
        iptype = "v6"
        print("\n" + "="*40)
        print("开始处理IPv6记录")
        print("="*40)
        main(cloud)
    
    print(f"\n" + "="*60)
    print(f"脚本执行完成: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
