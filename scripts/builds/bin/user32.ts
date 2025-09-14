// user32.ts
// manages the user32.dll

interface User32 {
  MessageBoxW: (hwnd: number, text: string, caption: string, type: number) => number;
}

declare const user32: User32;