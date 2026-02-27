import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json

if __name__ == "__main__":
  with open('botsv1.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

  results = [d['result'] for d in data if 'result' in d]
  df = pd.DataFrame(results)

  # analyze WinEventLog
  suspicious_win = []
  for idx, row in df[df['LogName'] == 'Security'].iterrows():
      event_code = str(row.get('EventCode', ''))
      proc_name = str(row.get('New_Process_Name', '')).lower()

      if event_code == '4625':
          suspicious_win.append('Ошибка входа (4625)')
      elif event_code == '4703':
          suspicious_win.append('Эскалация привилегий (4703)')
      elif event_code == '4688' and 'powershell' in proc_name:
          suspicious_win.append('Запуск PowerShell (4688)')

  win_df = pd.DataFrame({'Event': suspicious_win})
  win_counts = win_df['Event'].value_counts().reset_index()
  win_counts.columns = ['Event', 'Count']
  win_counts['Log_Type'] = 'WinEventLog'


  # analyze DNS logs
  suspicious_dns = []
  for idx, row in df[df['EventCode'] == 'DNS'].iterrows():
      query = str(row.get('QueryName', ''))
      event_types = row.get('eventtype', [])
      
      if isinstance(event_types, list) and 'suspicious' in event_types:
          suspicious_dns.append(f'Подозрительный DNS: {query}')
      elif len(query) > 25 or 'malicious' in query.lower():
          suspicious_dns.append(f'Вредоносный DNS запрос: {query}')

  dns_df = pd.DataFrame({'Event': suspicious_dns})
  dns_counts = dns_df['Event'].value_counts().reset_index()
  dns_counts.columns = ['Event', 'Count']
  dns_counts['Log_Type'] = 'DNS'

  # visualize
  combined = pd.concat([win_counts, dns_counts])
  top_10 = combined.sort_values('Count', ascending=False).head(10)

  top_10.to_csv('top_10_suspicious_events.csv', index=False)

  plt.figure(figsize=(10, 6))
  sns.set_theme(style="whitegrid")
  sns.barplot(
      data=top_10, 
      x='Count', 
      y='Event', 
      hue='Log_Type', 
      dodge=False, 
      palette='Set2'
  )

  plt.title('Топ-10 подозрительных событий (WinEventLog & DNS)', fontsize=14, fontweight='bold')
  plt.xlabel('Количество срабатываний', fontsize=12)
  plt.ylabel('Событие', fontsize=12)
  plt.tight_layout()

  plt.savefig('top_10_suspicious_events.png', dpi=300)
