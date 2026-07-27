@echo off
echo ====================================================================
echo [WSL Setup] Provisioning Ghostwire V7 Pentest Tools inside WSL...
echo ====================================================================
echo.
echo Running setup.sh inside WSL default Linux environment...
wsl -e bash -c "cd /tmp && sudo bash /mnt/c/Users/ASUS/Desktop/red\ team/setup.sh"
echo.
echo [WSL Setup] Done.
pause
