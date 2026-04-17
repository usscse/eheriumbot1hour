@echo off
title TSR Data Manager - Network Server
echo ==========================================
echo  TSR Data Manager Network Server
echo ==========================================
echo.
echo Starting server...
echo.
cd /d "%~dp0"
node server.js
pause