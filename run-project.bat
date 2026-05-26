@echo off

start cmd /k "cd /d D:\soc-final\backend && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 5 >nul

start cmd /k "cd /d D:\soc-final\frontend && npm run dev"

exit
