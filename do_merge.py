import os
import re
import glob

# Read files
with open('core/config_loader.py', 'r', encoding='utf-8') as f:
    config_loader = f.read()

with open('config_backends.py', 'r', encoding='utf-8') as f:
    config_backends = f.read()

with open('config_thresholds.py', 'r', encoding='utf-8') as f:
    config_thresholds = f.read()

with open('config_paths.py', 'r', encoding='utf-8') as f:
    config_paths = f.read()

with open('config.py', 'r', encoding='utf-8') as f:
    config_py = f.read()

# Strip imports from the individual files


def strip_imports(text, to_strip):
    for s in to_strip:
        # Match `from X import (...)` multi-line
        text = re.sub(
            r'from ' +
            re.escape(s) +
            r' import\s*\([^)]*\)',
            '',
            text,
            flags=re.MULTILINE)
        # Match `from X import Y, Z`
        text = re.sub(r'from ' + re.escape(s) + r' import .*?(\n|$)', '', text)
        # Match `import X`
        text = re.sub(r'import ' + re.escape(s) + r'\b.*?\n', '', text)
    return text


config_backends = strip_imports(config_backends, ['core.config_loader'])
config_thresholds = strip_imports(config_thresholds, ['core.config_loader'])
config_paths = strip_imports(
    config_paths, [
        'core.config_loader', 'config_thresholds'])
config_py = strip_imports(config_py,
                          ['core.config_loader',
                           'config_backends',
                           'config_thresholds',
                           'config_paths'])

# Combine
combined = config_loader + '\n\n' + config_backends + '\n\n' + \
    config_thresholds + '\n\n' + config_paths + '\n\n' + config_py

with open('core/unified_config_loader.py', 'w', encoding='utf-8') as f:
    f.write(combined)

# Replace imports in all python files
py_files = glob.glob('**/*.py', recursive=True)
for py_file in py_files:
    if py_file.replace('\\', '/') in ['config.py', 'config_backends.py', 'config_thresholds.py', 'config_paths.py',
                                      'core/config_loader.py', 'do_merge.py', 'core/unified_config_loader.py'] or '.venv' in py_file:
        continue

    try:
        with open(py_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in do_merge.py: {_e}')
        continue

    # We replace:
    # from config import ...
    # from config_paths import ...
    # from config_backends import ...
    # from config_thresholds import ...
    # from core.config_loader import ...

    new_content = re.sub(
        r'from (config|config_paths|config_backends|config_thresholds|core\.config_loader) import',
        r'from core.unified_config_loader import',
        content)

    # Replace direct imports
    new_content = re.sub(
        r'import config_paths',
        'import core.unified_config_loader as config_paths',
        new_content)
    new_content = re.sub(
        r'import config_backends',
        'import core.unified_config_loader as config_backends',
        new_content)
    new_content = re.sub(
        r'import config_thresholds',
        'import core.unified_config_loader as config_thresholds',
        new_content)
    new_content = re.sub(
        r'import config\b',
        'import core.unified_config_loader as config',
        new_content)

    if new_content != content:
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated imports in {py_file}")

# Delete old files
os.remove('config.py')
os.remove('config_backends.py')
os.remove('config_thresholds.py')
os.remove('config_paths.py')
os.remove('core/config_loader.py')
print("Deleted old config files")
