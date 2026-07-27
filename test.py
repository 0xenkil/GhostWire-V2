from core.wsl_executor import WSLExecutor
w = WSLExecutor()
cmd = "export PATH=$HOME/.local/bin:/root/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/opt/theHarvester:$PATH && which nmap 2>/dev/null || which nmap 2>/dev/null"
print(w.execute(cmd))
