@echo off
setlocal

set "GRADLE_VERSION=8.14.3"
set "BASE_DIR=%~dp0"
set "GRADLE_HOME=%BASE_DIR%.gradle\bootstrap\gradle-%GRADLE_VERSION%"
set "GRADLE_BIN=%GRADLE_HOME%\bin\gradle.bat"
set "GRADLE_ZIP=%BASE_DIR%.gradle\bootstrap\gradle-%GRADLE_VERSION%-bin.zip"

if not exist "%GRADLE_BIN%" (
  echo Bootstrapping Gradle %GRADLE_VERSION%...
  if not exist "%BASE_DIR%.gradle\bootstrap" mkdir "%BASE_DIR%.gradle\bootstrap"
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'https://services.gradle.org/distributions/gradle-%GRADLE_VERSION%-bin.zip' -OutFile '%GRADLE_ZIP%'"
  if errorlevel 1 exit /b 1
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%GRADLE_ZIP%' -DestinationPath '%BASE_DIR%.gradle\bootstrap' -Force"
  if errorlevel 1 exit /b 1
)

call "%GRADLE_BIN%" %*
