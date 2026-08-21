import pathlib

# Проверим auth.py
p = pathlib.Path('sentinel/auth.py')
c = p.read_text(encoding='utf-8')

# Ищем проблемные места где возвращается role
lines = c.split('\n')
print("Checking sentinel/auth.py for role return issues...")
print("=" * 70)

for i, line in enumerate(lines):
    if 'role' in line.lower() and ('return' in line or 'to_dict' in line or '.value' in line):
        print(f'{i+1}: {line}')

print()
print("=" * 70)
print("Checking if UserRole enum is properly converted...")

# Проверим APIKey.to_dict()
if 'def to_dict' in c:
    print("Found to_dict method, checking role field...")
    for i, line in enumerate(lines):
        if 'def to_dict' in line:
            # Показать следующие 20 строк
            for j in range(20):
                if i+j < len(lines):
                    print(f'{i+j+1}: {lines[i+j]}')
            break
