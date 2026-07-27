import sys
sys.path.append('C:/Users/ASUS/Desktop/red team')
from core.robust_parser import extract_json_object

test_str = '''
```json
{
  "conops": "Detailed concept of operations plan",
  "roe": "Specific rules of engagement constraints",
  "phases": ["phase1", "phase2"]
}
```
'''
print("Result:", extract_json_object(test_str))
