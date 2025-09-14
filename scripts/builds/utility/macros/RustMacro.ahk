; RustMacro.ahk - Handles Rust macros
; Author: Karim Sar
; Version: 1.0.0
; Last Updated: 9/7/2024
; Description: This script provides functionality to handle Rust macros in an efficient and professional manner.

#NoEnv  ; Recommended for performance and compatibility with future AutoHotkey releases.
#Warn  ; Enable warnings to assist with detecting common errors.
SendMode Input  ; Recommended for new scripts due to its superior speed and reliability.
SetWorkingDir %A_ScriptDir%  ; Ensures a consistent starting directory.

; Global variables
global rustMacroList := []
global macroExpansionDepth := 0
global maxMacroExpansionDepth := 100

; Function to initialize Rust macro handling
InitializeRustMacroHandler() {
    ; Load predefined macros from external file
    LoadPredefinedMacros()
    
    ; Set up hotkeys for macro expansion
    Hotkey, ^!m, ExpandMacro
    Hotkey, ^!r, ReloadMacroDefinitions
    
    ; Initialize macro expansion history
    global macroExpansionHistory := []
    
    ; Set up GUI for macro management
    CreateMacroManagementGUI()
}

; Function to load predefined macros from external file
LoadPredefinedMacros() {
    FileRead, macroData, %A_ScriptDir%\predefined_macros.json
    if (macroData != "") {
        parsedMacros := JSON.Load(macroData)
        for macroName, macroDefinition in parsedMacros {
            rustMacroList.Push({name: macroName, definition: macroDefinition})
        }
    }
}

; Function to expand a Rust macro
ExpandMacro() {
    if (macroExpansionDepth >= maxMacroExpansionDepth) {
        MsgBox, 0, Error, Maximum macro expansion depth reached. Possible recursive macro detected.
        return
    }
    
    macroExpansionDepth++
    
    ; Get the current selection
    ClipboardOld := ClipboardAll
    Clipboard := ""
    Send, ^c
    ClipWait, 2
    if ErrorLevel {
        MsgBox, 0, Error, Failed to get the current selection.
        macroExpansionDepth--
        return
    }
    macroCall := Clipboard
    
    ; Find matching macro
    matchedMacro := FindMatchingMacro(macroCall)
    if (matchedMacro) {
        expandedMacro := ExpandMacroDefinition(matchedMacro, macroCall)
        
        ; Replace the selection with the expanded macro
        Clipboard := expandedMacro
        Send, ^v
        
        ; Add to expansion history
        macroExpansionHistory.Push({original: macroCall, expanded: expandedMacro})
    } else {
        MsgBox, 0, Error, No matching macro found for: %macroCall%
    }
    
    Clipboard := ClipboardOld
    macroExpansionDepth--
}

; Function to find a matching macro for a given macro call
FindMatchingMacro(macroCall) {
    for index, macro in rustMacroList {
        if (RegExMatch(macroCall, "^" . macro.name . "!?\(.*\)$")) {
            return macro
        }
    }
    return false
}

; Function to expand a macro definition with given arguments
ExpandMacroDefinition(macro, macroCall) {
    ; Extract arguments from macro call
    args := ExtractMacroArguments(macroCall)
    
    ; Replace placeholders in macro definition with actual arguments
    expandedMacro := macro.definition
    for index, arg in args {
        expandedMacro := StrReplace(expandedMacro, "${" . index . "}", arg)
    }
    
    ; Handle nested macro calls
    while (RegExMatch(expandedMacro, "(\w+)!?\(.*\)")) {
        expandedMacro := ExpandMacro(expandedMacro)
    }
    
    return expandedMacro
}

; Function to extract arguments from a macro call
ExtractMacroArguments(macroCall) {
    args := []
    RegExMatch(macroCall, "\((.*)\)$", match)
    if (match1 != "") {
        argString := match1
        inQuotes := false
        currentArg := ""
        Loop, Parse, argString
        {
            if (A_LoopField == """") {
                inQuotes := !inQuotes
            } else if (A_LoopField == "," && !inQuotes) {
                args.Push(Trim(currentArg))
                currentArg := ""
            } else {
                currentArg .= A_LoopField
            }
        }
        if (currentArg != "") {
            args.Push(Trim(currentArg))
        }
    }
    return args
}

; Function to reload macro definitions
ReloadMacroDefinitions() {
    rustMacroList := []
    LoadPredefinedMacros()
    MsgBox, 0, Info, Macro definitions reloaded successfully.
}

; Function to create GUI for macro management
CreateMacroManagementGUI() {
    Gui, MacroManager:New, +Resize
    Gui, Add, ListView, r20 w500 gMacroListView, Macro Name|Macro Definition
    Gui, Add, Button, gAddMacro, Add Macro
    Gui, Add, Button, x+10 gEditMacro, Edit Macro
    Gui, Add, Button, x+10 gDeleteMacro, Delete Macro
    Gui, Add, Button, x+10 gSaveMacros, Save Macros
    Gui, Show, , Rust Macro Manager
    
    PopulateMacroListView()
}

; Function to populate the macro list view
PopulateMacroListView() {
    GuiControl, -Redraw, ListView1
    LV_Delete()
    for index, macro in rustMacroList {
        LV_Add("", macro.name, macro.definition)
    }
    GuiControl, +Redraw, ListView1
}

; Function to handle adding a new macro
AddMacro() {
    InputBox, macroName, Add Macro, Enter the macro name:
    if (ErrorLevel) {
        return
    }
    InputBox, macroDefinition, Add Macro, Enter the macro definition:
    if (ErrorLevel) {
        return
    }
    
    rustMacroList.Push({name: macroName, definition: macroDefinition})
    PopulateMacroListView()
}

; Function to handle editing an existing macro
EditMacro() {
    if (A_GuiEvent != "DoubleClick") {
        return
    }
    
    RowNumber := A_EventInfo
    if (RowNumber = 0) {
        return
    }
    
    LV_GetText(macroName, RowNumber, 1)
    LV_GetText(macroDefinition, RowNumber, 2)
    
    InputBox, newMacroName, Edit Macro, Enter the new macro name:, , , , , , , , %macroName%
    if (ErrorLevel) {
        return
    }
    InputBox, newMacroDefinition, Edit Macro, Enter the new macro definition:, , , , , , , , %macroDefinition%
    if (ErrorLevel) {
        return
    }
    
    rustMacroList[RowNumber] := {name: newMacroName, definition: newMacroDefinition}
    PopulateMacroListView()
}

; Function to handle deleting a macro
DeleteMacro() {
    RowNumber := LV_GetNext(0, "Focused")
    if (RowNumber = 0) {
        return
    }
    
    LV_GetText(macroName, RowNumber, 1)
    MsgBox, 4, Confirm Deletion, Are you sure you want to delete the macro "%macroName%"?
    IfMsgBox, Yes
    {
        rustMacroList.RemoveAt(RowNumber)
        PopulateMacroListView()
    }
}

; Function to save macros to external file
SaveMacros() {
    macroJSON := JSON.Dump(rustMacroList)
    FileSelectFile, outputFile, S16, predefined_macros.json, Save Macro Definitions, JSON Files (*.json)
    if (outputFile != "") {
        FileDelete, %outputFile%
        FileAppend, %macroJSON%, %outputFile%
        if (ErrorLevel) {
            MsgBox, 0, Error, Failed to save macro definitions.
        } else {
            MsgBox, 0, Success, Macro definitions saved successfully.
        }
    }
}

; Initialize the Rust macro handler
InitializeRustMacroHandler()

; Hotkey to open macro management GUI
^!g::
Gui, MacroManager:Show
return

; Auto-execute section
#If WinActive("ahk_class SciTEWindow")  ; Adjust this to match your Rust IDE
^Space::
    ExpandMacro()
return
#If

; Include necessary libraries
#Include %A_ScriptDir%\JSON.ahk
