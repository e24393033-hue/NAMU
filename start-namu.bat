@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo NAMU needs Node.js 24 or later to run its local database.
  echo Install Node.js from https://nodejs.org/ and then run this file again.
  pause
  exit /b 1
)
node server.js
if errorlevel 1 pause
