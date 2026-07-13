@echo off
setlocal enabledelayedexpansion
title Vanguard Log Translator

set "SCRIPT_PATH=%~dp0vanguard_log_translator.py"
set "DEFAULT_LOG_DIR=C:\Program Files\Riot Vanguard\Logs"

:: Dynamically query the Windows shell to get the actual Desktop path (prevents unicode/encoding issues)
for /f "usebackq tokens=*" %%i in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('Desktop')"`) do (
    set "DESKTOP_PATH=%%i"
)

echo ===================================================
echo             Vanguard Log Translator
echo ===================================================
echo.

if not "%~1"=="" goto has_arg

:menu
echo [1] Drag and drop a log file/folder onto this icon.
echo [2] Enter the path to the log file/folder manually.
echo [3] Auto-decrypt and translate default Vanguard logs to Desktop.
echo.
set /p "CHOICE=Select option (1, 2, or 3): "
if "!CHOICE!"=="1" (
    echo.
    echo [*] Please close this window and drag-and-drop a file or folder directly onto the batch file icon.
    pause
    exit /b
)
if "!CHOICE!"=="2" (
    echo.
    set /p "INPUT_FILE=Enter path: "
    set "INPUT_FILE=!INPUT_FILE:"=!"
    if "!INPUT_FILE!"=="" (
        echo [-] No path entered. Exiting...
        pause
        exit /b
    )
    goto run_translation
)
if "!CHOICE!"=="3" (
    echo.
    echo [*] Scanning default directory: !DEFAULT_LOG_DIR!
    set "INPUT_FILE=!DEFAULT_LOG_DIR!"
    set "OUTPUT_DIR=!DESKTOP_PATH!\Translated_Vanguard_Logs"
    echo [*] Output directory: !OUTPUT_DIR!
    echo.
    python "!SCRIPT_PATH!" "!INPUT_FILE!" "!OUTPUT_DIR!"
    if %errorlevel% equ 0 (
        echo.
        echo [+] Auto-decrypt and translation completed successfully!
        echo [+] Translated files are saved on your Desktop in "Translated_Vanguard_Logs".
    ) else (
        echo.
        echo [-] Error: Auto-translation failed. Make sure vanguard_log_translator.py is in the same folder.
    )
    echo.
    pause
    exit /b
)
echo [-] Invalid choice.
pause
cls
goto menu

:has_arg
set "INPUT_FILE=%~1"
echo [*] Translating: !INPUT_FILE!
goto run_translation

:run_translation
if not exist "!INPUT_FILE!" (
    echo [-] Error: Path does not exist: !INPUT_FILE!
    pause
    exit /b
)

for %%i in ("!INPUT_FILE!") do (
    set "FILE_DIR=%%~dpi"
    set "FILE_NAME=%%~nxi"
)

set "OUTPUT_FILE=!FILE_DIR!translated_!FILE_NAME!"

echo [*] Target translation output: !OUTPUT_FILE!
echo.

python "!SCRIPT_PATH!" "!INPUT_FILE!" "!OUTPUT_FILE!"
if %errorlevel% equ 0 (
    echo.
    echo [+] Translation completed successfully!
    echo [+] Output file: !OUTPUT_FILE!
) else (
    echo.
    echo [-] Error: Translation failed. Make sure vanguard_log_translator.py is in the same folder.
)

echo.
pause
