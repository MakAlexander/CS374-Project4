/*
smallsh
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
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_LENGTH 2048
#define MAX_ARGS 512

// Global variables for signal handling and status
volatile sig_atomic_t fg_only = 0;
int last_fg_status = 0;             // Tracks foreground process status
pid_t bg_pids[MAX_ARGS];
int bg_count = 0; 

// Command structure
struct command_line {
    char *argv[MAX_ARGS + 1];
    int argc;
    char *input_file;
    char *output_file;
    bool is_bg;
};

// Free allocated memory for command structure
void free_command(struct command_line *cmd) {
    for (int i = 0; i < cmd->argc; i++) {
        free(cmd->argv[i]);
    }
    if (cmd->input_file) free(cmd->input_file);
    if (cmd->output_file) free(cmd->output_file);
    free(cmd);
}

// Parse user input into a command structure
struct command_line *parse_input() {
    // # Code from Explorations: Shell Commands Related to Processes (sample_parser.c file)
    char input[MAX_LENGTH];
    struct command_line *cmd = calloc(1, sizeof(struct command_line));
    
    printf(": ");
    fflush(stdout);
    if (!fgets(input, MAX_LENGTH, stdin)) {  // Get input from stdin
        free(cmd);
        return NULL;
    }

    // Ignore blank lines or comments
    if (input[0] == '\n' || input[0] == '#') {
        free(cmd);
        return NULL;
    }

    char *token = strtok(input, " \n");
    while (token) {
        if (!strcmp(token, "<")) {
            token = strtok(NULL, " \n");
            if (token) cmd->input_file = strdup(token);
        } else if (!strcmp(token, ">")) {
            token = strtok(NULL, " \n");
            if (token) cmd->output_file = strdup(token);
        } else if (!strcmp(token, "&") && !strtok(NULL, " \n")) {
            cmd->is_bg = true;
        } else {
            cmd->argv[cmd->argc++] = strdup(token);
        }
        token = strtok(NULL, " \n");
    }
    cmd->argv[cmd->argc] = NULL;  // Null-terminate argv
    return cmd;
}

// Signal handler for SIGTSTP for foreground-only mode
void handle_SIGTSTP(int signo) {
    // # Code from Explorations: Signal Handling (custom signal handler example)
    char *msg = fg_only ? 
        "\nExiting foreground-only mode\n" :
        "\nEntering foreground-only mode (& is now ignored)\n";
    write(STDOUT_FILENO, msg, strlen(msg));  // # Code from Explorations: Signals Handling (reentrant Functions)
    fg_only = !fg_only; 
}

// Check and report terminated background processes
void check_background() {
    // # Code from Explorations: Process API - Monitoring Child Processes (waitpid with WNOHANG)
    int status;
    for (int i = 0; i < bg_count; i++) {
        pid_t pid = waitpid(bg_pids[i], &status, WNOHANG);  // Non-blocking wait
        if (pid > 0) {  // Child has terminated
            if (WIFEXITED(status)) {
                printf("background pid %d is done: exit value %d\n", 
                       pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("background pid %d is done: terminated by signal %d\n", 
                       pid, WTERMSIG(status));
            }
            fflush(stdout);
            // Remove PID from array
            bg_pids[i] = bg_pids[--bg_count];
            i--;
        }
    }
}

// Execute the parsed command
void execute_command(struct command_line *cmd) {
    if (cmd->argc == 0) return;

    // Built-in commands
    if (!strcmp(cmd->argv[0], "exit")) {
        // # Code from Explorations: Process API – Creating and Terminating Processes (exit)
        for (int i = 0; i < bg_count; i++) {
            kill(bg_pids[i], SIGTERM);  // # Code from Explorations: Signals – Concepts and Types (kill)
        }
        free_command(cmd);
        exit(0);  // Terminate shell
    } else if (!strcmp(cmd->argv[0], "cd")) {
        // # Code from Explorations: Environment (getenv)
        char *dir = cmd->argc > 1 ? cmd->argv[1] : getenv("HOME");
        if (chdir(dir) == -1) {  // # Standard POSIX function, implied in process discussions
            perror("chdir failed");
        }
    } else if (!strcmp(cmd->argv[0], "status")) {
        // # Code from Explorations: Process API - Monitoring Child Processes
        if (WIFEXITED(last_fg_status)) {
            printf("exit value %d\n", WEXITSTATUS(last_fg_status));
        } else if (WIFSIGNALED(last_fg_status)) {
            printf("terminated by signal %d\n", WTERMSIG(last_fg_status));
        }
        fflush(stdout);
    } else {
        // External command execution
        pid_t pid;
        int status;

        // # Code from Explorations: Process API - Creating and Terminating Processes (fork)
        pid = fork();
        if (pid < 0) {
            perror("fork failed");
            exit(1);
        }
        if (pid == 0) {  // Child process
            // Reset signals for child
            // # Code from Explorations: Signals – Concepts and Types (signal reset)
            signal(SIGINT, SIG_DFL);  // Default SIGINT behavior
            signal(SIGTSTP, SIG_IGN); // Ignore SIGTSTP

            // Input redirection
            // # Code from Explorations: Processes and I/O (dup2 for redirection)
            if (cmd->input_file) {
                int fd = open(cmd->input_file, O_RDONLY);
                if (fd < 0) {
                    printf("cannot open %s for input\n", cmd->input_file);
                    fflush(stdout);
                    exit(1);
                }
                dup2(fd, STDIN_FILENO);  // Redirect stdin
                close(fd);
            } else if (cmd->is_bg && !fg_only) {
                int fd = open("/dev/null", O_RDONLY);
                dup2(fd, STDIN_FILENO);
                close(fd);
            }

            // Output redirection
            // # Code from Explorations: Processes and I/O (dup2 for redirection)
            if (cmd->output_file) {
                int fd = open(cmd->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd < 0) {
                    printf("cannot open %s for output\n", cmd->output_file);
                    fflush(stdout);
                    exit(1);
                }
                dup2(fd, STDOUT_FILENO);  // Redirect stdout
                close(fd);
            } else if (cmd->is_bg && !fg_only) {
                int fd = open("/dev/null", O_WRONLY);
                dup2(fd, STDOUT_FILENO);
                close(fd);
            }

            // Executes command
            // # Code from Explorations: Process API - Executing a New Program (execvp)
            execvp(cmd->argv[0], cmd->argv);
            printf("%s: no such file or directory\n", cmd->argv[0]);
            fflush(stdout);
            exit(1);  // Exit if exec fails
            
        } else {  // Parent process
            bool is_bg = cmd->is_bg && !fg_only;
            if (is_bg) {
                printf("background pid is %d\n", pid);
                fflush(stdout);
                bg_pids[bg_count++] = pid;  // Store background PID
            } else {
                // # Code from Explorations: Process API - Monitoring Child Processes (waitpid)
                pid_t result = waitpid(pid, &last_fg_status, 0);  // Blocking wait
                if (result < 0) {
                    perror("waitpid failed");
                }
                if (WIFSIGNALED(last_fg_status)) {
                    printf("terminated by signal %d\n", WTERMSIG(last_fg_status));
                    fflush(stdout);
                }
            }
        }
    }
}

// Main shell loop
int main() {
    // Signal setup
    // # Code from Explorations: Handling Signals (signal and sigaction)
    signal(SIGINT, SIG_IGN);  // Ignore SIGINT in parent
    
    struct sigaction sa = {0};
    sa.sa_handler = handle_SIGTSTP;  // Custom handler for SIGTSTP
    sa.sa_flags = SA_RESTART;        // Restart interrupted system calls
    sigaction(SIGTSTP, &sa, NULL);   // Register handler

    while (true) {
        check_background();  // Check for completed background processes
        struct command_line *cmd = parse_input();
        if (cmd) {
            execute_command(cmd);
            free_command(cmd);
        }
    }
    return 0;
}