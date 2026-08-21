import pathlib

p = pathlib.Path('sentinel/evidence_store.py')
c = p.read_text(encoding='utf-8')

# Показать что есть сейчас
lines = c.split('\n')
for i, line in enumerate(lines):
    if 'def _get_evidence_file' in line:
        print('Found _get_evidence_file:')
        for j in range(6):
            if i+j < len(lines):
                print(f'{i+j}: {lines[i+j]}')
        break

# Заменить простой санитайзер
new_lines = []
for line in lines:
    if 'safe_agent_id = agent_id.replace("/", "_").replace("\\\\", "_")' in line:
        indent = '        '
        new_lines.append(f'{indent}safe_agent_id = self._safe_agent_id(agent_id)')
    else:
        new_lines.append(line)

new_content = '\n'.join(new_lines)
p.write_text(new_content, encoding='utf-8')
print()
print('OK: Fixed _get_evidence_file to use _safe_agent_id()')
