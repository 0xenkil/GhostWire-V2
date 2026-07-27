from core.wsl_executor import WSLExecutor
from core.waf_ghost_engine import WafGhostEngine
import sys
import os
sys.path.append(os.getcwd())

executor = WSLExecutor()
engine = WafGhostEngine(remote_executor=executor)
cmd = 'curl https://dash.novalink.lk/auth/login'
print('Original:', cmd)
res = engine.solve_challenge(cmd)
print('Result:', res)
