# Keystone keyboard reference

Every Keystone command starts from the command layer. Press NVDA+slash, release it, then press the command key below. Keystone calls this sequence KLS. Press KLS, then H at any time to hear this list read aloud. Each entry reads as the keystroke followed by what it does.

- NVDA+/, then S: Capture foreground with configured limits.
- NVDA+/, then Shift+S: Capture foreground with process-safety limits.
- NVDA+/, then F: Capture focus-object subtree with process-safety limits.
- NVDA+/, then D: Capture or compare the foreground diff.
- NVDA+/, then N: Capture navigator object with configured limits.
- NVDA+/, then Shift+N: Capture navigator object with process-safety limits.
- NVDA+/, then Shift+O: Capture navigator-object subtree with process-safety limits.
- NVDA+/, then I: Open Inspector for focus.
- NVDA+/, then O: Open Inspector for navigator object.
- NVDA+/, then E: Open Event Monitor.
- NVDA+/, then F5: Start or stop Event Monitor.
- NVDA+/, then C: Manage Custom UIA Properties.
- NVDA+/, then H: Show Keystone command help.

While a capture or diff command is running, press the same command again to request cancellation at the next safe boundary. After a result is committed, press the same command again quickly to copy its file path, then once more to reveal it in Explorer.

Inspector and Event Monitor are two pages of the same Keystone Inspector window. NVDA+/, then E selects the current live focus before opening Event Monitor. NVDA+/, then F5 starts or stops Event Monitor from any application. Ctrl+I selects Inspector and Ctrl+E selects Event Monitor. Tab and Shift+Tab use normal native traversal, including the Close button below the pages. In Inspector, Ctrl+F opens native Find and F3 or Shift+F3 repeats the most recent hierarchy search. In the Annotations properties list, Alt+T shows the selected annotation target. Hierarchy and property context menus provide Copy, Inspect this element, Monitor this element, and Show annotation target actions where applicable.
