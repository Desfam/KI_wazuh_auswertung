@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b %errorlevel%
set PATH=%PATH%;%USERPROFILE%\.cargo\bin
cd /d d:\PYTHON\KI_wazuh_auswertung\desktop\tauri
cargo run
