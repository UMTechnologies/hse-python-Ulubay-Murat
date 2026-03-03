import asyncio
import pyshark
import pandas as pd
import matplotlib.pyplot as plt

def analyze_pcap(file_path):
    print(f"--- Начинаю анализ файла: {file_path} ---")
    
    artifacts = []
    
    capture = pyshark.FileCapture(file_path)
    
    for packet in capture:
        try:
            timestamp = packet.sniff_time
            protocol = packet.highest_layer
            src_ip = packet.ip.src if 'IP' in packet else "N/A"
            dst_ip = packet.ip.dst if 'IP' in packet else "N/A"
            info = ""

            if 'DNS' in packet:
                if hasattr(packet.dns, 'qry_name'):
                    info = f"DNS Query: {packet.dns.qry_name}"
            
            elif 'DHCP' in packet:
                info = f"DHCP Event (ID: {packet.dhcp.get('option.dhcp_server_id', 'N/A')})"
                if hasattr(packet.dhcp, 'option_dhcp_message_type'):
                    info = f"DHCP Message Type: {packet.dhcp.option_dhcp_message_type}"

            artifacts.append({
                'time': timestamp,
                'src': src_ip,
                'dst': dst_ip,
                'protocol': protocol,
                'info': info
            })
            
        except AttributeError:
            continue

    capture.close()
    
    df = pd.DataFrame(artifacts)
    
    
    df.to_csv('analysis_results.csv', index=False)
    print("Результаты сохранены в analysis_results.csv")
    
    print("\nСписок обнаруженных IP-адресов:")
    unique_ips = pd.concat([df['src'], df['dst']]).unique()
    print([ip for ip in unique_ips if ip != "N/A"])

    plt.figure(figsize=(10, 6))
    df['protocol'].value_counts().plot(kind='bar', color='skyblue', edgecolor='black')
    plt.title('Распределение протоколов в дампе')
    plt.xlabel('Протокол')
    plt.ylabel('Количество пакетов')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.savefig('protocol_stats.png')
    print("График активности сохранен в protocol_stats.png")
    plt.show()

    return 1

if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    analyze_pcap('dhcp.pcapng')