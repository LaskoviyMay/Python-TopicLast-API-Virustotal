import os
import requests
import time
import zipfile
from datetime import datetime

# Данные архива
ARCHIVE_PATH = 'archive/protected_archive.zip'
PASSWORD = b'netology'  # Пароль в байтах

# Директория распаковки
EXTRACT_DIR = 'extracted'

# Файл отчета
REPORT_FILE = 'report.txt'

# Данные API
API_KEY = '69c6e5b0753784312c9193ac1e65a38d2cb35667d98a2cbebe671da9fb5e8004'
HEADERS = {'x-apikey': API_KEY}

# Целевые антивирусы
TARGET_AV = {'Fortinet', 'McAfee', 'Yandex', 'Sophos'}

# Параметры анализа
MAX_ANALYSIS_TIME = 300  # Максимальное время анализа 5 минут
CHECK_INTERVAL = 30      # Проверять каждые 30 секунд

def extract_archive():
    """Распаковка архива"""
    try:
        with zipfile.ZipFile(ARCHIVE_PATH) as zf:
            zf.extractall(EXTRACT_DIR, pwd=PASSWORD)
            print(f"[+] Архив распакован в директорию {EXTRACT_DIR}")
            return True
    except Exception as e:
        print(f"[-] Ошибка распаковки архива: {e}")
        return False

def upload_file(file_path):
    """Загрузка файла на VirusTotal"""
    if not os.path.exists(file_path):
        return {"error": f"Файл {file_path} не найден"}
    
    try:
        with open(file_path, 'rb') as f:
            response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers=HEADERS,
                files={'file': (os.path.basename(file_path), f)}
            )
            
        if response.status_code == 200:
            return {"analysis_id": response.json()['data']['id']}
        return {"error": f"Ошибка загрузки файла: {response.status_code}"}
    except Exception as e:
        return {"error": f"Критическая ошибка загрузки файла: {str(e)}"}

def get_analysis_status(analysis_id):
    """Проверка статуса анализа"""
    start_time = datetime.now()
    
    while (datetime.now() - start_time).seconds < MAX_ANALYSIS_TIME:
        try:
            response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers=HEADERS
            )
            
            if response.status_code != 200:
                return None
                
            report = response.json()
            status = report.get('data', {}).get('attributes', {}).get('status')
            
            if status == 'completed':
                return report
            if status in ['queued', 'in_progress']:
                print(f"[!] Анализ {status}, ожидание...")
                time.sleep(CHECK_INTERVAL)
                continue
            return None
            
        except Exception as e:
            print(f"[-] Ошибка проверки статуса: {e}")
            time.sleep(CHECK_INTERVAL)
    
    print(f"[-] Таймаут анализа {analysis_id}")
    return None

def analyze_report(report):
    """Анализ отчета VirusTotal"""
    if not report:
        return None
        
    stats = {
        'total': 0,
        'malicious': 0,
        'detected_by': [],
        'target_av': {'detected': [], 'not_detected': []}
    }
    
    results = report.get('data', {}).get('attributes', {}).get('results', {})
    for av, data in results.items():
        stats['total'] += 1
        if data.get('category') == 'malicious':
            stats['malicious'] += 1
            stats['detected_by'].append(av)
            if av in TARGET_AV:
                stats['target_av']['detected'].append(av)
        elif av in TARGET_AV:
            stats['target_av']['not_detected'].append(av)
            
    return stats

def get_behaviour_summary(file_id):
    try:
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_id}/behaviour_summary',
            headers=HEADERS
        )
        
        if response.status_code == 200:
            return response.json()
        print(f"[-] Sandbox отчёт недоступен: {response.status_code}")
        return None
    except Exception as e:
        print(f"[-] Критическая ошибка получения отчета Sandbox: {e}")
        return None

def analyze_behaviour_report(behaviour_data):
    if not behaviour_data:
        return None, None, None
    
    try:
        attributes = behaviour_data.get('data', {}).get('attributes', {})
        network = attributes.get('network', {})
        
        domains = network.get('domains', [])
        ips = network.get('ips', [])
        behavior = attributes.get('behavior', 'Описание поведения недоступно')
        
        return domains, ips, behavior
    except KeyError:
        return [], [], 'Ошибка структуры отчёта'

def generate_report(stats, filename, domains=None, ips=None, behavior=None):
    if not stats:
        return
        
    with open(REPORT_FILE, 'a', encoding='utf-8') as f:
        # Отчет антивирусов
        f.write(f"Отчет для: {filename}\n{'='*40}\n")
        f.write("\n=== VirusTotal Antivirus Statistics ===\n")
        f.write(f"Обнаружено: {stats['malicious']}/{stats['total']}\n")
        f.write("Антивирусы:\n" + "\n".join([f"- {av}" for av in stats['detected_by']]) + "\n\n")
        f.write("Целевые антивирусы:\n")
        f.write(f"Обнаружили: {', '.join(stats['target_av']['detected'])}\n")
        f.write(f"Не обнаружили: {', '.join(stats['target_av']['not_detected'])}\n")
        
        # Отчет Sandbox
        f.write("\n=== VirusTotal Sandbox ===\n")
        if domains is not None and ips is not None:
            f.write(f"Поведение: {behavior if behavior else 'Нет данных'}\n")
            f.write("\nДомены для блокировки:\n")
            f.write('\n'.join([f"- {d}" for d in domains]) if domains else "- Нет данных")
            f.write("\n\nIP-адреса для блокировки:\n")
            f.write('\n'.join([f"- {ip}" for ip in ips]) if ips else "- Нет данных")
        else:
            f.write("Отчёт недоступен (требуется подписка)\n")

def main():
    # Подготовка окружения
    if os.path.exists(REPORT_FILE):
        os.remove(REPORT_FILE)
    if not extract_archive():
        return

    # Обработка файлов
    for root, _, files in os.walk(EXTRACT_DIR):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"[*] Обработка файла {file}")

            try:
                # Загрузка файла
                upload_result = upload_file(file_path)
                if 'error' in upload_result:
                    print(upload_result['error'])
                    continue  # Пропуск текущей итерации при ошибке загрузки

                analysis_id = upload_result['analysis_id']
                print(f"[+] ID анализа: {analysis_id}")

                # Получение результатов
                report = get_analysis_status(analysis_id)
                if not report:
                    print("[-] Не удалось получить отчет")
                    continue

                # Получение данных для отчета антивирусов
                stats = analyze_report(report)
                if not stats:
                    print("[-] Ошибка анализа отчета")
                    continue

                # Получение SHA256 из отчета
                file_sha256 = report.get('data', {}).get('attributes', {}).get('sha256', '')
                if not file_sha256:
                    # Если SHA256 нет в атрибутах, извлекается из URL
                    item_url = report.get('data', {}).get('links', {}).get('item', '')
                    file_sha256 = item_url.split('/')[-1] if item_url else ''

                # Генерация отчета антивирусов
                if not file_sha256:
                    print("[-] SHA256 не найден")
                    generate_report(stats, file)  # Генерируем отчет без Sandbox
                    continue

                # Получение данных для отчета Sandbox
                behaviour_data = get_behaviour_summary(file_sha256)
                domains, ips, behavior = analyze_behaviour_report(behaviour_data)

                # Генерация отчета Sandbox
                generate_report(stats, file, domains, ips, behavior)
                print(f"[+] Отчет для {file} сохранен")

            except Exception as e:
                print(f"Ошибка при обработке файла {file}: {e}")
                continue  # Пропуск текущей итерации при возникновении исключения

if __name__ == "__main__":
    main()