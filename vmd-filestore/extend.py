# Читаем исходный файл
with open('comtrade_data.dat', 'r') as f:
    lines = f.readlines()

# Парсим последнюю строку, чтобы узнать на чем мы остановились
last_line = lines[-1].strip().split(',')
current_index = int(last_line[0])
current_time = int(last_line[1])
time_step = 250 # Шаг времени из ваших данных

MULTIPLIER = 3 # Сколько раз скопировать данные

new_lines =[]

for _ in range(MULTIPLIER):
    for line in lines:
        parts = line.strip().split(',')
        if len(parts) < 4:
            continue
            
        current_index += 1
        current_time += time_step
        
        # Берем значения токов/напряжений (3-й столбец) и цифровые данные (4-й) из оригинала
        val1 = parts[2]
        val2 = parts[3]
        
        new_lines.append(f"{current_index},{current_time},{val1},{val2}\n")

# Дописываем новые строки в конец файла
with open('comtrade_data.dat', 'a') as f:
    f.writelines(new_lines)

print(f"Готово! Добавлено {len(new_lines)} новых строк.")
