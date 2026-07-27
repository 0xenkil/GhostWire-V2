import os
import re

intelligence_dir = r"C:\Users\ASUS\Desktop\red team\intelligence"

extraction_func = """
            def _extract_json(resp, is_array=False):
                import re, json, logging
                match = re.search(r'```(?:json)?\\s*(.*?)\\s*```', resp, re.DOTALL)
                if match:
                    try: return json.loads(match.group(1))
                    except Exception as e:
                        logging.error(f"Markdown JSON extract failed: {e}")

                pattern = r'\\[[\\s\\S]*?\\]' if is_array else r'\\{[\\s\\S]*?\\}'
                # Try finding all matches and parsing the longest one
                matches = re.findall(pattern, resp)
                if matches:
                    matches.sort(key=len, reverse=True)
                    for m in matches:
                        try: return json.loads(m)
                        except Exception: continue

                # Last resort fallback to greedy (maybe valid)
                greedy_pattern = r'\\[[\\s\\S]*\\]' if is_array else r'\\{[\\s\\S]*\\}'
                gmatch = re.search(greedy_pattern, resp)
                if gmatch:
                    try: return json.loads(gmatch.group(0))
                    except Exception as e:
                        logging.error(f"Greedy JSON extract failed: {e}")

                raise ValueError("Could not extract valid JSON from response.")
"""

for root, _, files in os.walk(intelligence_dir):
    for file in files:
        if not file.endswith(".py"):
            continue
        filepath = os.path.join(root, file)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        modified = False

        # Replace dictionary matches
        # The pattern looks like: match = re.search(r'\{[\s\S]*\}', response)\n            if match:\n                var_name = json.loads(match.group(0))
        # We need a regex to match this

        # We will just do a string replacement for the most common parts
        dict_pattern = re.compile(
            r"match\s*=\s*re\.search\(r'\\{\[\\s\\S\]\*\\}',\s*([a-zA-Z0-9_]+)\)\s*\n\s*if\s*match:\s*\n\s*([a-zA-Z0-9_]+)\s*=\s*json\.loads\(match\.group\(0\)\)")

        def repl_dict(m):
            resp_var = m.group(1)
            assign_var = m.group(2)
            return extraction_func.strip(
                "\n") + f"\n            {assign_var} = _extract_json({resp_var}, is_array=False)"

        new_content, count1 = dict_pattern.subn(repl_dict, content)

        arr_pattern = re.compile(
            r"match\s*=\s*re\.search\(r'\\[\\[\\s\\S\]\*\\]',\s*([a-zA-Z0-9_]+)\)\s*\n\s*if\s*match:\s*\n\s*([a-zA-Z0-9_]+)\s*=\s*json\.loads\(match\.group\(0\)\)")

        def repl_arr(m):
            resp_var = m.group(1)
            assign_var = m.group(2)
            return extraction_func.strip(
                "\n") + f"\n            {assign_var} = _extract_json({resp_var}, is_array=True)"

        new_content, count2 = arr_pattern.subn(repl_arr, new_content)

        if count1 > 0 or count2 > 0:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed {count1 + count2} matches in {file}")
