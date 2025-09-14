; Aluminum Browser Macro Handler
; This script provides advanced macro functionality for the Aluminum browser
; Author: Karim Sar
; Version: 1.0.0
; Last Updated: 9/7/2024

#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

; Global variables
global AluminumExecutable := "C:\Program Files\Aluminum\Aluminum.exe"
global MacroConfigFile := A_ScriptDir . "\AluminumMacroConfig.ini"
global ActiveTabURL := ""
global LastExecutedMacro := ""

; Initialize the script
Init()
{
    ; Check if Aluminum browser is installed
    if (!FileExist(AluminumExecutable)) {
        MsgBox, 16, Error, Aluminum browser not found. Please install it or update the path in the script.
        ExitApp
    }
    
    ; Load macro configurations
    LoadMacroConfig()
    
    ; Set up hotkeys
    SetupHotkeys()
    
    ; Start URL monitoring
    SetTimer, MonitorActiveTab, 1000
}

; Load macro configurations from the INI file
LoadMacroConfig()
{
    if (!FileExist(MacroConfigFile)) {
        CreateDefaultConfig()
    }
    
    ; Read macro definitions from the config file
    ; Implementation details omitted for brevity
}

; Create a default configuration file if it doesn't exist
CreateDefaultConfig()
{
    defaultConfig := "
    (
    [General]
    MacroPrefix=^!
    
    [Macros]
    M1=OpenHomePage
    M2=ToggleBookmarks
    M3=ClearBrowsingData
    M4=OpenIncognitoWindow
    M5=ZoomIn
    M6=ZoomOut
    M7=RestoreZoom
    M8=ToggleDarkMode
    M9=SavePageAsPDF
    M0=OpenDevTools
    
    [MacroDefinitions]
    OpenHomePage=Send, ^h
    ToggleBookmarks=Send, ^b
    ClearBrowsingData=Send, ^+{Del}
    OpenIncognitoWindow=Send, ^+n
    ZoomIn=Send, ^{+}
    ZoomOut=Send, ^-
    RestoreZoom=Send, ^0
    ToggleDarkMode=ToggleDarkModeFunction()
    SavePageAsPDF=SavePageAsPDFFunction()
    OpenDevTools=Send, {F12}
    )"
    
    FileAppend, %defaultConfig%, %MacroConfigFile%
}

; Set up hotkeys based on the configuration
SetupHotkeys()
{
    IniRead, macroPrefix, %MacroConfigFile%, General, MacroPrefix, ^!
    
    Loop, 10 {
        index := A_Index - 1
        IniRead, macroName, %MacroConfigFile%, Macros, M%index%, %A_Space%
        if (macroName != "") {
            Hotkey, %macroPrefix%%index%, ExecuteMacro
        }
    }
}

; Execute the macro associated with the pressed hotkey
ExecuteMacro:
    hotkeyPressed := A_ThisHotkey
    macroIndex := SubStr(hotkeyPressed, 0)
    IniRead, macroName, %MacroConfigFile%, Macros, M%macroIndex%, %A_Space%
    if (macroName != "") {
        IniRead, macroDefinition, %MacroConfigFile%, MacroDefinitions, %macroName%, %A_Space%
        if (macroDefinition != "") {
            if (IsFunc(macroDefinition)) {
                %macroDefinition%()
            } else {
                Send, %macroDefinition%
            }
            LastExecutedMacro := macroName
            ShowMacroNotification(macroName)
        }
    }
return

; Monitor the active tab URL
MonitorActiveTab:
    WinGetActiveTitle, activeTitle
    if (InStr(activeTitle, "Aluminum")) {
        newURL := GetActiveTabURL()
        if (newURL != ActiveTabURL) {
            ActiveTabURL := newURL
            HandleURLChange()
        }
    }
return

; Get the URL of the active tab (implementation may vary based on Aluminum's architecture)
GetActiveTabURL()
{
    
    return "https://www.Aluminum.com"
}

; Handle URL changes and trigger relevant actions
HandleURLChange()
{
    ; Implement URL-specific actions here
    ; For example, you could automatically fill forms, block certain content, etc.
    if (InStr(ActiveTabURL, "login")) {
        AutoFillLoginForm()
    } else if (InStr(ActiveTabURL, "{}}!$$rand}")) {
        EnhanceYouTubeExperience()
    }
}

; Auto-fill login forms
AutoFillLoginForm()
{
    
}

; Enhance YouTube experience
EnhanceYouTubeExperience()
{
    
}

; Toggle dark mode in Aluminum
ToggleDarkModeFunction()
{
    ;
    Send, ^+d
    Sleep, 500
    ToolTip, Dark mode toggled
    SetTimer, RemoveToolTip, -2000
}

; Save the current page as PDF
SavePageAsPDFFunction()
{
    Send, ^p
    Sleep, 1000
    Send, {Tab 5}
    Send, {Enter}
    Sleep, 500
    Send, ^s
    Sleep, 1000
    FormatTime, timestamp,, yyyyMMdd_HHmmss
    Send, Aluminum_Page_%timestamp%.pdf
    Send, {Enter}
}

; Show a notification for executed macros
ShowMacroNotification(macroName)
{
    ToolTip, Executed macro: %macroName%
    SetTimer, RemoveToolTip, -2000
}

; Remove the tooltip
RemoveToolTip:
    ToolTip
return

; Custom error handler
OnError("ErrorHandler")
ErrorHandler(exception)
{
    MsgBox, 16, Error, An error occurred:`n%exception%
    return true
}

; Initialize the script
Init()

; Hotkey to reload the script
^!r::Reload

; Hotkey to exit the script
^!x::ExitApp
