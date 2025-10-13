#define _POSIX_C_SOURCE 200809L

#include "msgs.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_ARGS 128
#define MAX_LEN 1024

char *input_history[MAX_LEN];
int history_len = 0;

int current_dir(char *cwd, size_t size) {
  if (!getcwd(cwd, size)) {
    char *msg = FORMAT_MSG("shell", GETCWD_ERROR_MSG);
    write(STDERR_FILENO, msg, strlen(msg));
    return -1;
  }

  char sign[] = "$ ";
  write(STDOUT_FILENO, cwd, strlen(cwd)); // write $ in the main()
  write(STDOUT_FILENO, sign, strlen(sign));
  return 0;
}

int sep_line(char *line, char **elements) {
  size_t len = 0;
  char *input_str = line;
  char *delim = " \t\n\r";
  char *token = NULL;
  char *saveptr = NULL;

  while ((token = strtok_r(input_str, delim, &saveptr))) {
    elements[len] = token;
    len++;

    input_str = NULL;
  }
  elements[len] = NULL;
  return (int)len;
}

void add_history(char *input) {
  if (history_len >= MAX_LEN)
    return;
  char *copy = strdup(input);
  if (!copy)
    return;
  input_history[history_len++] = copy;
}

void print_history() {
  int len = history_len;
  if (history_len >= 10) {
    len = 10;
  }
  for (int i = 0; i < len; i++) {
    int index = history_len - 1 - i;
    char buf[64];
    int n = snprintf(buf, sizeof buf, "%d\t", index);
    write(STDOUT_FILENO, buf, (size_t)n);
    write(STDOUT_FILENO, input_history[index], strlen(input_history[index]));
    write(STDOUT_FILENO, "\n", 1);
  }
}

int read_line(char *input, char **tokens, _Bool *is_background) {
  *is_background = false;

  ssize_t n = read(STDIN_FILENO, input, MAX_LEN - 1);
  if (n < 0) {
    char *msg = FORMAT_MSG("shell", READ_ERROR_MSG);
    write(STDERR_FILENO, msg, strlen(msg));
    return -1;
  }

  input[n] = '\0';

  if (n > 0 && input[n - 1] == '\n') {
    input[n - 1] = '\0';
  }

  if (input[0] != '!' && input[0] != '\0') {
    add_history(input);
  }

  int token_count = sep_line(input, tokens);
  if (token_count == 0) {
    return 0;
  } else {
    if (strcmp(tokens[token_count - 1], "&") == 0) {
      *is_background = true;
      tokens[token_count - 1] = NULL;
      token_count--;
    }
  }
  return token_count;
}

void exec_command(char **token, int len, _Bool in_background, char *cwd);

int internal_commands(char **tokens, int len, char *cwd) {
  // Check there is any command or not;
  if (len <= 0 || tokens[0] == NULL) {
    return -1;
  }

  static char prev_dir[PATH_MAX] = "";

  // For exit;
  if (strcmp(tokens[0], "exit") == 0) {
    if (tokens[1] != NULL) {
      char *msg = FORMAT_MSG("exit", TMA_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }
    exit(0);
    return 1;
  }
  // For pwd;
  else if (strcmp(tokens[0], "pwd") == 0) {
    char cwd[PATH_MAX];

    if (tokens[1] != NULL) {
      char *msg = FORMAT_MSG("pwd", TMA_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }

    if (!getcwd(cwd, sizeof(cwd))) {
      char *msg = FORMAT_MSG("pwd", GETCWD_ERROR_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }
    write(STDOUT_FILENO, cwd, strlen(cwd));
    write(STDOUT_FILENO, "\n", 1);
    return 1;
  }
  // For cd;
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }

    // Initialize the variables of new directory;
    int change_dir = -1;
    char new_dir[PATH_MAX];
    // For home directory;
    uid_t uid = getuid();
    struct passwd *pwd = getpwuid(uid);

    if (tokens[1] == NULL || strcmp(tokens[1], "~") == 0) {
      strcpy(new_dir, pwd->pw_dir);
      change_dir = chdir(new_dir);
    } else if (tokens[1][0] == '~') {
      snprintf(new_dir, sizeof(new_dir), "%s%s", pwd->pw_dir, tokens[1] + 1);
      new_dir[sizeof(new_dir) - 1] = '\0';
      change_dir = chdir(new_dir);
    } else if (strcmp(tokens[1], "-") == 0) {
      if (strcmp(prev_dir, "") != 0) {
        strcpy(new_dir, prev_dir);
        change_dir = chdir(new_dir);
      }
    } else {
      strcpy(new_dir, tokens[1]);
      change_dir = chdir(new_dir);
    }

    if (change_dir == -1) {
      char *msg = FORMAT_MSG("cd", CHDIR_ERROR_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    } else {
      strcpy(prev_dir, cwd);
    }
    return 1;
  }
  // For help;
  else if (strcmp(tokens[0], "help") == 0) {
    if (tokens[2] != NULL) {
      char *msg = FORMAT_MSG("help", TMA_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }

    char *msg1 = FORMAT_MSG("help", HELP_HELP_MSG);
    char *msg2 = FORMAT_MSG("exit", EXIT_HELP_MSG);
    char *msg3 = FORMAT_MSG("pwd", PWD_HELP_MSG);
    char *msg4 = FORMAT_MSG("cd", CD_HELP_MSG);
    char *msg5 = FORMAT_MSG("history", HISTORY_HELP_MSG);
    if (tokens[1] == NULL) {
      write(STDOUT_FILENO, msg1, strlen(msg1));
      write(STDOUT_FILENO, msg2, strlen(msg2));
      write(STDOUT_FILENO, msg3, strlen(msg3));
      write(STDOUT_FILENO, msg4, strlen(msg4));
      write(STDOUT_FILENO, msg5, strlen(msg5));
    } else if (strcmp(tokens[1], "help") == 0) {
      write(STDOUT_FILENO, msg1, strlen(msg1));
    } else if (strcmp(tokens[1], "exit") == 0) {
      write(STDOUT_FILENO, msg2, strlen(msg2));
    } else if (strcmp(tokens[1], "pwd") == 0) {
      write(STDOUT_FILENO, msg3, strlen(msg3));
    } else if (strcmp(tokens[1], "cd") == 0) {
      write(STDOUT_FILENO, msg4, strlen(msg4));
    } else if (strcmp(tokens[1], "history") == 0) {
      write(STDOUT_FILENO, msg5, strlen(msg5));
    } else {
      write(STDOUT_FILENO, tokens[1], strlen(tokens[1]));
      write(STDOUT_FILENO, ": ", strlen(": "));
      write(STDOUT_FILENO, EXTERN_HELP_MSG, strlen(EXTERN_HELP_MSG));
      write(STDOUT_FILENO, "\n", 1);
    }
    return 1;
  }
  // For history;
  else if (strcmp(tokens[0], "history") == 0) {
    if (tokens[1] != NULL) {
      char *msg = FORMAT_MSG("history", HISTORY_INVALID_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }
    if (history_len == 0) {
      char *msg = FORMAT_MSG("history", HISTORY_NO_LAST_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      write(STDERR_FILENO, "\n", 1);
      return -1;
    }
    print_history();
    return 1;
  }
  // Handle with !;
  else if (tokens[0][0] == '!') {
    if (tokens[1] != NULL) {
      return -1;
    }

    if (history_len == 0) {
      const char *msg = FORMAT_MSG("history", HISTORY_NO_LAST_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      return -1;
    }
    // For !!;
    if (tokens[0][1] == '!') {
      char *output = input_history[history_len - 1];
      write(STDOUT_FILENO, output, strlen(output));
      write(STDOUT_FILENO, "\n", 1);

      // Run last command
      char *last_com[MAX_ARGS];
      _Bool back = false;
      if (output[0] != '\0') {
        add_history(output);
      }
      int t = sep_line(output, last_com);
      if (t == 0)
        return 1;
      else {
        if (strcmp(last_com[t - 1], "&") == 0) {
          back = true;
          last_com[t - 1] = NULL;
          t--;
        }
        exec_command(last_com, t, back, cwd);
      }
      return 1;
    }
    // For !n;
    else {
      _Bool isNum = true;
      for (int i = 1; tokens[0][i] != '\0'; i++) {
        if (!isdigit((unsigned char)tokens[0][i])) {
          isNum = false;
          break;
        }
      }
      if (isNum) {
        int index = atoi(&tokens[0][1]);
        if (index < history_len - 10 || index > history_len - 1) {
          const char *msg = FORMAT_MSG("history", HISTORY_INVALID_MSG);
          write(STDERR_FILENO, msg, strlen(msg));
          return -1;
        }
        char *output = input_history[index];
        write(STDOUT_FILENO, output, strlen(output));
        write(STDOUT_FILENO, "\n", 1);
        // Run last command
        char *last_com[MAX_ARGS];
        _Bool back = false;
        if (output[0] != '\0') {
          add_history(output);
        }
        int t = sep_line(output, last_com);
        if (t == 0)
          return 1;
        else {
          if (strcmp(last_com[t - 1], "&") == 0) {
            back = true;
            last_com[t - 1] = NULL;
            t--;
          }
          exec_command(last_com, t, back, cwd);
        }
      } else {
        const char *msg = FORMAT_MSG("history", HISTORY_INVALID_MSG);
        write(STDERR_FILENO, msg, strlen(msg));
        return -1;
      }
      return 1;
    }
  }

  return 0;
}

void exec_command(char **tokens, int len, _Bool in_background, char *cwd) {
  if (len <= 0 || tokens[0] == NULL) {
    return;
  }

  int result = internal_commands(tokens, len, cwd);
  if (result != 0) {
    return;
  }

  pid_t pid;
  while (true) { // SIGINT interrupted fork
    errno = 0;
    pid = fork();
    if (pid == -1 && errno == EINTR)
      continue;
    break;
  }

  if (pid == -1) {
    char *msg = FORMAT_MSG("shell", FORK_ERROR_MSG);
    write(STDERR_FILENO, msg, strlen(msg));
    return;
  }
  if (pid == 0) {
    if (execvp(tokens[0], tokens) == -1) {
      char *msg = FORMAT_MSG("shell", EXEC_ERROR_MSG);
      write(STDERR_FILENO, msg, strlen(msg));
      exit(1); // Clean up zombie cild
      return;
    }
  } else {
    if (!in_background) {
      pid_t wpid;

      while (true) { // SIGINT interrupted waitpid
        errno = 0;
        wpid = waitpid(pid, NULL, 0);
        if (wpid == -1) {
          if (errno == EINTR) {
            return;
          }
          char *msg = FORMAT_MSG("shell", WAIT_ERROR_MSG);
          write(STDERR_FILENO, msg, strlen(msg));
          return;
        }
      }
    }
    int status = 0;
    while (waitpid(-1, &status, WNOHANG) > 0) {
    }
  }
}

// For SIGINT
void handle_SIGINT(int sig) {
  char *msg1 = FORMAT_MSG("help", HELP_HELP_MSG);
  char *msg2 = FORMAT_MSG("exit", EXIT_HELP_MSG);
  char *msg3 = FORMAT_MSG("pwd", PWD_HELP_MSG);
  char *msg4 = FORMAT_MSG("cd", CD_HELP_MSG);
  char *msg5 = FORMAT_MSG("history", HISTORY_HELP_MSG);
  write(STDOUT_FILENO, "\n", 1);
  write(STDOUT_FILENO, msg1, strlen(msg1));
  write(STDOUT_FILENO, msg2, strlen(msg2));
  write(STDOUT_FILENO, msg3, strlen(msg3));
  write(STDOUT_FILENO, msg4, strlen(msg4));
  write(STDOUT_FILENO, msg5, strlen(msg5));
}

int main() {
  // Set up signal
  struct sigaction sig;
  sig.sa_handler = handle_SIGINT;
  sig.sa_flags = 0;
  sigemptyset(&sig.sa_mask);
  sig.sa_handler = handle_SIGINT;
  sig.sa_flags = 0;
  sigemptyset(&sig.sa_mask);

  int ret = sigaction(SIGINT, &sig, NULL);
  if (ret == -1) {
    perror("Sigaction() failed");
    exit(EXIT_FAILURE);
  }
  // Main loop:
  while (true) {
    //  Initializ the variables;
    char *tokens[MAX_ARGS] = {NULL};
    char cwd[PATH_MAX];
    int a = current_dir(cwd, sizeof(cwd));
    if (a == -1) {
      continue;
    }

    // Read user input;
    char input[MAX_LEN];
    _Bool is_background = false;
    int len = read_line(input, tokens, &is_background);
    if (len == -1) {
      continue;
    }

    // Excute command;
    exec_command(tokens, len, is_background, cwd);
  }

  return 0;
}
