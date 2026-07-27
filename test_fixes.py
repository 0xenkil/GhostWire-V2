from unittest.mock import MagicMock
from agents.base_agent import BaseAgent
import sys
sys.path.insert(0, r'C:\Users\ASUS\Desktop\red team')

# Create a mock agent
agent = MagicMock()
agent.log = MagicMock()
agent._canonicalize_tool_command = BaseAgent._canonicalize_tool_command.__get__(
    agent)

cmd1 = agent._canonicalize_tool_command(
    'ffuf', 'ffuf -H "Host: usageapi.novalink.lk" http://usageapi.novalink.lk/')
print('FFUF FIX:', cmd1)

cmd2 = agent._canonicalize_tool_command(
    'masscan', 'masscan -p80,443 $(dig +short usageapi.216.198.79.1)')
print('MASSCAN FIX:', cmd2)

cmd3 = agent._canonicalize_tool_command(
    'gobuster',
    'gobuster -H "en;q=0.9" -a "Mozilla/5.0" dir -u http://usageapi.novalink.lk/')
print('GOBUSTER FIX:', cmd3)

cmd4 = agent._canonicalize_tool_command(
    'hydra', 'hydra -l admin -p admin http://usageapi.novalink.lk/login')
print('HYDRA FIX:', cmd4)
