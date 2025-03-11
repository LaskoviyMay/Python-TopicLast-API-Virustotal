Программирование на Python

Итоговое домашнее задание по 3-му модулю

Часть 1. Разработка инструмента для анализа киберугроз с
использованием VirusTotal API

Исходные данные

Архив ZIP с файлами для анализа. Файл protected_archive.zip.

Пароль: netology

Внимание: файл действительно является вредоносным, поэтому, несмотря на
обфускацию, когда вы выполните его распаковку на актуальных версиях Windows, он
будет помещён в карантин из-за подозрения на вредоносность.
Этапы выполнения задания (часть 1)

Этап 1. Распаковка архива.
 Используя Python, распакуйте предоставленный архив и извлеките файлы.

Этап 2. Анализ файлов через VirusTotal API.
 Отправьте файлы на анализ, используя ваш персональный API-ключ VirusTotal.

Этап 3. Обработка результатов сканирования.
 Проанализируйте ответы от VirusTotal, собирая данные о детектировании угроз
антивирусами.

Этап 4. Подготовка отчёта. Составьте отчёт со статистикой результатов сканирования.
Включите в отчёт код скрипта и результат его вывода в виде скриншота (JPG, PNG).
 Приведите список антивирусов, которые обнаружили угрозы, в формате:
Detected, ALYac, Kaspersky.
 Сравните результаты с заданным списком антивирусов и песочниц. Укажите,
какие из указанных антивирусов (Fortinet, McAfee, Yandex, Sophos)
детектировали угрозу, а какие нет.

Дополнительные задачи
● Если доступен отчёт VirusTotal Sandbox о поведении вредоноса,
проанализируйте его и включите в свой отчёт ключевые моменты из него.
● Выведите список доменов и IP-адресов, с которыми вредонос общается, (для
блокировки) и описание поведения (Behavior) от VirusTotal Sandbox, если оно
доступно
