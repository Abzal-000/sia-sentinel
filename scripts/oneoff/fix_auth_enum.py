import pathlib, re

p = pathlib.Path('sentinel/auth.py')
c = p.read_text(encoding='utf-8')

# Фикс 1: APIKey.to_dict() - убедиться что role это строка
c = re.sub(
    r'("role": self\.role)(?!.*\.value)',
    r'\1.value',
    c
)

# Фикс 2: User.to_dict() - убедиться что role это строка  
c = re.sub(
    r'("role": self\.role)(?!.*\.value)',
    r'\1.value',
    c
)

p.write_text(c, encoding='utf-8')
print('OK: Fixed role enum conversion in auth.py')
