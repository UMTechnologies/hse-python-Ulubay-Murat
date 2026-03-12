import json
import os
import requests
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# Эмуляция работы Suricata
# ==========================================
def generate_dummy_suricata_logs(filename="suricata_logs.json"):
    if not os.path.exists(filename):
        dummy_logs = [
            {"timestamp": "2023-10-01T12:00:00", "event_type": "alert", "src_ip": "192.168.23.15", "dest_ip": "103.45.67.89", "alert": {"signature": "Suspicious DNS traffic"}},
            {"timestamp": "2023-10-01T12:05:00", "event_type": "alert", "src_ip": "192.168.23.20", "dest_ip": "185.20.10.5", "alert": {"signature": "Malware C2 communication"}},
            {"timestamp": "2023-10-01T12:10:00", "event_type": "alert", "src_ip": "192.168.23.15", "dest_ip": "8.8.8.8", "alert": {"signature": "Normal DNS query"}},
            {"timestamp": "2023-10-01T12:15:00", "event_type": "alert", "src_ip": "192.168.23.50", "dest_ip": "185.20.10.5", "alert": {"signature": "Malware C2 communication"}}
        ]
        with open(filename, 'w') as f:
            for log in dummy_logs:
                f.write(json.dumps(log) + '\n')

# ==========================================
# Этап 1: Сбор данных
# ==========================================
def load_suricata_logs(filename="suricata_logs.json"):
    print("Чтение логов Suricata...")
    ips_to_check = set()
    with open(filename, 'r') as f:
        for line in f:
            log_entry = json.loads(line.strip())
            ips_to_check.add(log_entry.get("dest_ip"))
    return list(ips_to_check)

def check_ip_virustotal(ip):
    """
    Эмуляция API VirusTotal
    """
    threat_database = {
        "103.45.67.89": {"malicious": 8, "suspicious": 2},
        "185.20.10.5": {"malicious": 15, "suspicious": 5},
        "8.8.8.8": {"malicious": 0, "suspicious": 0}
    }
    
    result = threat_database.get(ip, {"malicious": 0, "suspicious": 0})
    return {"ip": ip, "score": result["malicious"]}

# ==========================================
# Этап 2 и 3: Анализ данных и реагирование
# ==========================================
def analyze_and_respond(ips):
    print("\nАнализ данных с последующим реагированием...")
    report_data = []
    
    for ip in ips:
        api_result = check_ip_virustotal(ip)
        score = api_result["score"]
        
        status = "Safe"
        if score > 5:
            status = "Critical Threat"
            print(f"  [!] НАЙДЕНА УГРОЗА! IP: {ip} (Оценка опасности: {score})")
            print(f"      -> СКРИПТ: Вызов скрипта на фаерволе. IP {ip} ЗАБЛОКИРОВАН.")
            print(f"      -> УВЕДОМЛЕНИЕ: Отправка алерта в Telegram администратору...\n")
        elif score > 0:
            status = "Suspicious"
            print(f"  [?] ПОДОЗРИТЕЛЬНЫЙ ТРАФИК. IP: {ip} (Оценка опасности: {score})")
            print(f"      -> СКРИПТ: IP добавлен в лист наблюдения.\n")
        else:
            print(f"  [OK] IP {ip} безопасен.")
            
        report_data.append({
            "IP Address": ip,
            "Threat Score": score,
            "Status": status
        })
        
    return pd.DataFrame(report_data)

# ==========================================
# Этап 4: Формирование отчёта
# ==========================================
def generate_reports(df):
    print("\nФормирование отчётов...")
    
    # CSV
    csv_filename = "threat_report.csv"
    df.to_csv(csv_filename, index=False)
    print(f"Отчёт сохранён в {csv_filename}")
    
    # JSON
    json_filename = "threat_report.json"
    df.to_json(json_filename, orient="records", indent=4)
    print(f"Отчёт сохранён в {json_filename}")
    
    # Seaborn/Matplotlib
    plt.figure(figsize=(8, 5))
    sns.set_theme(style="whitegrid")
    
    if not df.empty:
        ax = sns.barplot(
            x="IP Address", 
            y="Threat Score", 
            data=df, 
            palette="Reds_d", 
            hue="IP Address",
            legend=False
        )
        plt.title("Уровень опасности проверенных IP-адресов", fontsize=14)
        plt.xlabel("IP Адрес", fontsize=12)
        plt.ylabel("Кол-во срабатываний (Threat Score)", fontsize=12)
        
        plt.axhline(5, color='red', linestyle='--', label='Критический порог')
        plt.legend()

        png_filename = "threat_chart.png"
        plt.savefig(png_filename, dpi=300, bbox_inches='tight')
        print(f"График сохранён в {png_filename}")


if __name__ == "__main__":
    generate_dummy_suricata_logs()

    print("Запуск системы реагирования...")
    unique_ips = load_suricata_logs()
    results_df = analyze_and_respond(unique_ips)
    generate_reports(results_df)
    
    print("Завершение работы...")
