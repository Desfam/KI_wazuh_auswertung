@echo off
setlocal

set "VSDEVCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"

if not exist "%VSDEVCMD%" (
  echo [ERROR] Visual Studio Build Tools environment not found.
  echo         Expected: "%VSDEVCMD%"
  echo         Install "Visual Studio BuildTools 2022" with the C++ workload.
  exit /b 1
)

call "%VSDEVCMD%" -arch=x64 -host_arch=x64
if errorlevel 1 (
  echo [ERROR] Failed to initialize Visual Studio developer environment.
  exit /b 1
)

set "PATH=%PATH%;%USERPROFILE%\.cargo\bin"

cd /d "%~dp0frontend"
if errorlevel 1 (
  echo [ERROR] Could not switch to frontend directory.
  exit /b 1
)

echo [INFO] Building frontend assets...
npm run build
if errorlevel 1 (
  echo [ERROR] Frontend build failed.
  exit /b 1
)

cd /d "%~dp0desktop\tauri"
if errorlevel 1 (
  echo [ERROR] Could not switch to desktop\tauri directory.
  exit /b 1
)

cargo run
exit /b %errorlevel%
