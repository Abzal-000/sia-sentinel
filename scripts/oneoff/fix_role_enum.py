import pathlib, re

p = pathlib.Path('sentinel/auth.py')
c = p.read_text(encoding='utf-8')

# Фикс 1: _load_keys - конвертировать строку в UserRole enum
old_load = '''    def _load_keys(self) -> None:
        \"\"\"Load keys from disk.\"\"\"
        if self.keys_file.exists():
            with open(self.keys_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key_data in data.get("keys", []):
                    key = APIKey(**key_data)
                    self.keys[key.key_id] = key'''

new_load = '''    def _load_keys(self) -> None:
        \"\"\"Load keys from disk.\"\"\"
        if self.keys_file.exists():
            with open(self.keys_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for key_data in data.get("keys", []):
                    # Convert role string back to UserRole enum
                    if isinstance(key_data.get("role"), str):
                        key_data["role"] = UserRole(key_data["role"])
                    key = APIKey(**key_data)
                    self.keys[key.key_id] = key'''

c = c.replace(old_load, new_load)

# Фикс 2: to_dict - безопасно получить значение role
old_to_dict = '''            "role": self.role.value,'''
new_to_dict = '''            "role": self.role.value if isinstance(self.role, UserRole) else self.role,'''
c = c.replace(old_to_dict, new_to_dict)

# Фикс 3: _save_keys - безопасно получить значение role
old_save = '''                    "role": k.role.value,'''
new_save = '''                    "role": k.role.value if isinstance(k.role, UserRole) else k.role,'''
c = c.replace(old_save, new_save)

# Фикс 4: User.to_dict - безопасно получить значение role
c = c.replace(
    '            "role": self.role.value,\n            "permissions":',
    '            "role": self.role.value if isinstance(self.role, UserRole) else self.role,\n            "permissions":'
)

p.write_text(c, encoding='utf-8')
print('OK: Fixed role enum handling in auth.py')
print('  - _load_keys now converts string to UserRole')
print('  - to_dict and _save_keys handle both enum and string')
