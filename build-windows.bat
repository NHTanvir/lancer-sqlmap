@echo off
REM Windows release build for lancer-sqlmap.
REM Output: dist\lancer-sqlmap-windows-x86_64\bin\lancer-sqlmap.exe

echo === Building lancer-sqlmap (release) for Windows x86_64 ===
cargo build --release -p lancer-sqlmap
if errorlevel 1 exit /b 1

echo === Packaging ===
set DIST=dist\lancer-sqlmap-windows-x86_64
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\bin"

copy target\release\lancer-sqlmap.exe "%DIST%\bin\" >nul
if exist LICENSE copy LICENSE "%DIST%\" >nul
if exist README.md copy README.md "%DIST%\" >nul

echo === Done. Binary: %DIST%\bin ===
dir "%DIST%\bin"
exit /b 0
