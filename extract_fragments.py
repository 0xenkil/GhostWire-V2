import glob
import os
import re

log_dir = r'C:\Users\ASUS\.gemini\antigravity\brain'
transcripts = glob.glob(
    os.path.join(
        log_dir,
        '*',
        '.system_generated',
        'logs',
        'transcript.jsonl'))

files_to_recover = {}

for path in transcripts:
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                if 'write_to_file' in line or 'replace_file_content' in line:
                    if 'TargetFile' in line and '.py' in line:
                        m_file = re.search(
                            r'"TargetFile"\s*:\s*"([^"]+\.py)"', line)
                        if m_file:
                            target = m_file.group(1).replace('\\\\', '/')
                            if 'red team' not in target:
                                continue

                            if 'write_to_file' in line:
                                m_code = re.search(
                                    r'"CodeContent"\s*:\s*"(.*?)"(?:,|})', line)
                                if m_code:
                                    code = m_code.group(1).encode(
                                        'utf-8').decode('unicode_escape')
                                    if target not in files_to_recover or len(
                                            code) > len(files_to_recover[target]):
                                        files_to_recover[target] = code
                            elif 'replace_file_content' in line:
                                k = target + '_edit'
                                m_chunks = re.search(
                                    r'"Replacement(?:Chunks|Content)"\s*:\s*(.*)', line)
                                if m_chunks:
                                    code = m_chunks.group(1)
                                    if k not in files_to_recover or len(
                                            code) > len(files_to_recover[k]):
                                        files_to_recover[k] = code
    except Exception as _e:
        import logging
        logging.getLogger(__name__).debug(
            f'Swallowed exception in extract_fragments.py: {_e}')

for k, v in files_to_recover.items():
    print(f'Recovered {k} ({len(v)} bytes)')
    out_name = os.path.basename(k).replace('/', '_') + '.fragment.txt'
    with open(out_name, 'w', encoding='utf-8') as f:
        f.write(v)
