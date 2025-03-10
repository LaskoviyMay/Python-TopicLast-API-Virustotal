import os
import requests
import time
import json
import shutil
from pathlib import Path

# Настройки
API_KEY = '69c6e5b0753784312c9193ac1e65a38d2cb35667d98a2cbebe671da9fb5e8004'
HEADERS = {'x-apikey': API_KEY}

INPUT_DIR = 'files_to_scan'         # Папка с файлами для проверки
PROCESSED_DIR = 'processed_files'   # Папка для обработанных файлов
REPORT_FILE = 'vt_analysis_report.txt'

# Создаем необходимые директории
Path(INPUT_DIR).mkdir(exist_ok=True)
Path(PROCESSED_DIR).mkdir(exist_ok=True)

def scan_file(file_path: Path) -> dict:
    """Загружает и анализирует файл через VirusTotal API v3"""
    try:
        # 1. Загрузка файла
        with open(file_path, 'rb') as f:
            response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers=HEADERS,
                files={'file': (file_path.name, f)}
            )
            response.raise_for_status()
            analysis_id = response.json()['data']['id']
            print(f"[+] Файл {file_path.name} загружен (ID: {analysis_id})")
        
        # 2. Ожидание завершения анализа
        analysis = wait_for_analysis(analysis_id)
        if not analysis:
            print(f"[-] Не удалось получить анализ для {file_path.name}")
            return {}
            
        # 3. Получение детального отчета
        return analysis['data']['attributes']
        
    except Exception as e:
        print(f"[-] Ошибка при анализе {file_path.name}: {str(e)}")
        return {}

def wait_for_analysis(analysis_id: str, retries=10, delay=30) -> dict:
    """Ожидает завершения анализа"""
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    
    for _ in range(retries):
        try:
            response = requests.get(url, headers=HEADERS)
            response.raise_for_status()
            report = response.json()
            
            if report['data']['attributes']['status'] == 'completed':
                return report
                
            print(f"[!] Анализ не завершен. Ожидание {delay} сек...")
            time.sleep(delay)
            
        except Exception as e:
            print(f"[-] Ошибка проверки анализа: {str(e)}")
            break
            
    print(f"[-] Таймаут ожидания анализа для ID: {analysis_id}")
    return {}

def generate_report(attributes: dict, file_name: str):
    """Формирует отчет по результатам анализа"""
    if not attributes:
        return
        
    stats = attributes['stats']
    results = attributes['results']
    sandbox = attributes.get('sandbox', {})
    
    detected_avs = [av for av, data in results.items() if data['category'] == 'malicious']
    target_avs = ['Fortinet', 'McAfee', 'Yandex', 'Sophos']
    
    with open(REPORT_FILE, 'a', encoding='utf-8') as f:
        f.write(f"\n=== Отчет для файла: {file_name} ===\n")
        f.write(f"MD5: {attributes['md5']}\n")
        f.write(f"SHA-256: {attributes['sha256']}\n")
        f.write(f"Размер: {attributes['size']} байт\n")
        f.write(f"Вредоносных вердиктов: {stats['malicious']}/{len(results)}\n")
        
        f.write("\n--- Обнаружившие антивирусы ---\n")
        for av in detected_avs:
            f.write(f"- {av}\n")
            
        f.write("\n--- Целевые антивирусы ---\n")
        for av in target_avs:
            status = "Обнаружил" if av in detected_avs else "Не обнаружил"
            f.write(f"{av}: {status}\n")
            
        if sandbox:
            f.write("\n--- Данные песочницы ---\n")
            f.write(f"Домены: {', '.join(sandbox.get('domains', []))}\n")
            f.write(f"IP-адреса: {', '.join(sandbox.get('ips', []))}\n")
            f.write(f"Поведение: {sandbox.get('behavior', {}).get('description', 'Нет данных')}\n")

def move_processed(file_path: Path):
    """Перемещает обработанный файл"""
    try:
        shutil.move(str(file_path), os.path.join(PROCESSED_DIR, file_path.name))
        print(f"[+] Файл {file_path.name} перемещен в {PROCESSED_DIR}")
    except Exception as e:
        print(f"[-] Ошибка перемещения {file_path.name}: {str(e)}")

def main():
    print("[*] Начинаем анализ файлов...")
    
    for file_path in Path(INPUT_DIR).iterdir():
        if file_path.is_file():
            print(f"\n[*] Обрабатываем файл: {file_path.name}")
            attributes = scan_file(file_path)
            generate_report(attributes, file_path.name)
            move_processed(file_path)
    
    print(f"\n[+] Анализ завершен! Отчет сохранен в {REPORT_FILE}")

if __name__ == "__main__":
    main()