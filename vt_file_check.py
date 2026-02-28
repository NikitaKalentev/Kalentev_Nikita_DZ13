# -*- coding: utf-8 -*-
"""
Python-скрипт для взаимодействия с API VirusTotal.

"""

import os
import requests
import json

FILE_HASH = "44d88612fea8a8f36de82e1278abb02f"  # EICAR test file hash

# --- 1. АВТОРИЗАЦИЯ ---
# Получаем API-ключ из переменной окружения. Это безопаснее, чем хранить его в коде.
API_KEY = os.getenv("VT_API_KEY")

# Проверяем, найден ли ключ
if not API_KEY:
    # Если ключ не найден, выводим подробную инструкцию и завершаем работу.
    print("="*60)
    print("ОШИБКА: API ключ не найден!")
    print("="*60)
    print("Необходимо настроить переменную окружения 'VT_API_KEY'.")
    print("Инструкция:")
    print("1. Получите ключ на virustotal.com.")
    print("2. В командной строке выполните:")
    print("   Windows: setx VT_API_KEY \"ВАШ_КЛЮЧ\" (перезапустите терминал после этого)")
    print("   macOS/Linux: export VT_API_KEY=\"ВАШ_КЛЮЧ\" (или добавьте в ~/.bashrc)")
    print("3. Запустите скрипт снова.")
    print("="*60)
    exit(1)  # Завершаем скрипт с кодом ошибки

print("[+] API ключ успешно загружен из переменной окружения.")

# --- 2. ФОРМИРОВАНИЕ ЗАПРОСА ---
# Базовый URL для API v3 VirusTotal
url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"

# Заголовки запроса. Авторизация происходит через заголовок x-apikey.
headers = {
    "x-apikey": API_KEY,
    "Accept": "application/json"  # Явно указываем, что ждем JSON в ответе
}

print(f"[+] Отправка запроса для файла с хэшем: {FILE_HASH}")

# --- 3. ВЫПОЛНЕНИЕ ЗАПРОСА И ОБРАБОТКА ОТВЕТА ---
try:
    # Выполняем GET-запрос к API
    response = requests.get(url, headers=headers, timeout=30)  # Таймаут в 30 секунд

    # Проверяем, успешен ли запрос (код 200)
    if response.status_code == 200:
        print("[+] Запрос выполнен успешно (код 200).")

        # Парсим JSON-ответ в объект Python (словарь)
        data = response.json()

        # --- 4. ВЫВОД РЕЗУЛЬТАТОВ ---
        # Выводим весь JSON-ответ в консоль в отформатированном виде.
        print("\n--- ПОЛНЫЙ JSON-ОТВЕТ ---")
        print(json.dumps(data, indent=4, ensure_ascii=False))  # ensure_ascii для русского языка
        print("--- КОНЕЦ JSON-ОТВЕТА ---\n")

        # Дополнительно, для наглядности, выводим статистику сканирования.
        try:
            # Извлекаем статистику из структуры ответа
            stats = data["data"]["attributes"]["last_analysis_stats"]
            print("--- СТАТИСТИКА СКАНИРОВАНИЯ ---")
            print(f"  Вредоносных (malicious):    {stats['malicious']}")
            print(f"  Подозрительных (suspicious): {stats['suspicious']}")
            print(f"  Безопасных (harmless):       {stats['harmless']}")
            print(f"  Неопределенных (undetected): {stats['undetected']}")
            print("--------------------------------")
        except KeyError as e:
            # Если структура ответа изменилась или для файла нет статистики
            print(f"[!] Не удалось извлечь статистику. Отсутствует ключ: {e}")

    else:
        # Если сервер вернул ошибку (например, 404 - файл не найден, 401 - не авторизован)
        print(f"[!] Ошибка HTTP: {response.status_code}")
        print("[!] Ответ сервера:")
        try:
            # Пытаемся вывести JSON-ошибку от сервера
            error_data = response.json()
            print(json.dumps(error_data, indent=4))
        except:
            # Если ответ не в JSON, выводим как текст
            print(response.text)

except requests.exceptions.Timeout:
    print("[!] Ошибка: Превышено время ожидания ответа от сервера.")
except requests.exceptions.ConnectionError:
    print("[!] Ошибка: Не удалось подключиться к серверу. Проверьте интернет-соединение.")
except requests.exceptions.RequestException as e:
    # Любая другая ошибка при выполнении запроса
    print(f"[!] Произошла ошибка при выполнении запроса: {e}")
except Exception as e:
    # Непредвиденная ошибка
    print(f"[!] Непредвиденная ошибка: {e}")

print("\n[✓] Работа скрипта завершена.")