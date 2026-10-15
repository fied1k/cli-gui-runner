@echo off
title CLI Quick-Reference & Multi-Cheat Sheet Runner
cd /d "%~dp0"
python cli_gui_runner.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ============================================================
    echo [ERROR] Script exited with error code %ERRORLEVEL%.
    echo ============================================================
    echo.
    pause
)
