import sys
sys.path.append('C:/Users/ASUS/Desktop/red team')
from core.robust_parser import extract_json_object

test_str = '''
```json
{
  "ConOps": "Detailed concept of operations plan",
  "RoE": "Specific rules of engagement constraints",
  "phases": ["phase1", "phase2"]
}
```
some garbage trailing text
'''
print("Result:", extract_json_object(test_str))
