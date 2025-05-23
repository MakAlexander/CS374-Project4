# smallsh

This program implements a basic shell environment with the following features:
- Reads commands from standard input and interprets built-in commands (cd, status, exit).
- Executes non-builtin commands by forking child processes and optionally placing them in the background.
- Supports input & output redirection using '<' and '>'.
- Tracks the status of the most recent foreground process (exit code or terminating signal).
- Monitors and cleans up background processes as they complete.
- Toggles a "foreground-only mode" via SIGTSTP (Ctrl+Z).

The user can:
1. Change directories (cd) or view the status (status) of the last foreground process.
2. Launch commands in the foreground or (optionally) in the background using '&'.
3. Redirect input or output files with '<' or '>'.
4. Exit the shell (exit), terminating all background processes.

