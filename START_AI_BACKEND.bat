@echo off
echo ================================================================
echo   RakshaLink AI Security Backend - Starting...
echo   http://127.0.0.1:5001
echo   Keep this window open while using the AI Guardian
echo ================================================================
cd /d "%~dp0ai-security-core"
python app.py
pause
