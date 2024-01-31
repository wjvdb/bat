@echo off
setlocal enabledelayedexpansion

for %%F in (*) do (
    if not "%%~xF"=="" (
        if not "%%~xF"==".bat" (
            if not "%%~xF"==".%download" (
                if not exist "%%~xF" (
                    mkdir "%%~xF"
                )
                move "%%F" "%%~xF"
            )
        )
    )
)
