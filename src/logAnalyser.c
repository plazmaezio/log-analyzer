// No Nginx parser used
#include "log_parser.h"
#include "event_classifier.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>

#define COLOR_RED "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_RESET "\033[0m"

const char *get_mode_name(int mode)
{
  switch (mode)
  {
  case MODE_SECURITY:
    return "security";
  case MODE_PERFORMANCE:
    return "performance";
  case MODE_TRAFFIC:
    return "traffic";
  case MODE_FULL:
    return "full";
  default:
    return "unknown"; // Return a default string or NULL if the mode is invalid
  }
}

void assign_analysis_mode(const char *mode_str, AnalysisMode *mode)
{
  if (strcmp(mode_str, "security") == 0)
  {
    *mode |= MODE_SECURITY;
  }
  else if (strcmp(mode_str, "performance") == 0)
  {
    *mode |= MODE_PERFORMANCE;
  }
  else if (strcmp(mode_str, "traffic") == 0)
  {
    *mode |= MODE_TRAFFIC;
  }
  else if (strcmp(mode_str, "full") == 0)
  {
    *mode |= MODE_FULL;
  }
  else
  {
    fprintf(stderr, "Unknown mode: %s\n", mode_str);
    exit(1);
  }
}

const char *get_severity_color(int severity)
{
  switch (severity)
  {
  case 4:
    return COLOR_RED; // CRITICAL
  case 3:
    return COLOR_RED; // HIGH
  case 2:
    return COLOR_YELLOW; // MEDIUM
  case 1:
    return COLOR_GREEN; // LOW
  default:
    return COLOR_RESET; // INFO
  }
}

void print_event(const ClassifiedEvent *event, AnalysisMode mode)
{
  // Filtrar por modo
  if (!event_matches_mode(event, mode))
  {
    return;
  }

  const char *color = get_severity_color(event->severity);

  printf("%s[%s] %s - %s%s\n",
         color,
         get_severity_name(event->severity),
         get_event_type_name(event->event_types),
         event->description,
         COLOR_RESET);
}

int isDirectory(const char *path)
{
  struct stat path_stat;
  if (stat(path, &path_stat) == -1)
  {
    fprintf(stderr, "Error: Unable to access '%s'.\n", path);
    return -1;
  }

  if (!S_ISDIR(path_stat.st_mode))
  {
    fprintf(stderr, "Error: '%s' is not a directory. This tool requires a directory path.\n", path);
    return 0;
  }

  return 1;
}

static void parse_options(int argc, char *argv[],
                          char *log_dir,
                          int *num_processes,
                          AnalysisMode *mode,
                          int *verbose,
                          char **output_file)
{
  if (argc < 4)
  {
    fprintf(stderr, "Usage: %s <log_dir> <num_processes> <mode> [--verbose] [--output=FILE]\n", argv[0]);
    fprintf(stderr, "Modes: security | performance | traffic | full\n");
    exit(1);
  }

  // Mandatory
  strcpy(log_dir, argv[1]);
  *num_processes = atoi(argv[2]);
  assign_analysis_mode(argv[3], mode);

  if (!isDirectory(log_dir))
  {
    exit(1);
  }

  // Defaults
  *verbose = 0;
  *output_file = NULL;

  // Optional
  for (int i = 4; i < argc; i++)
  {
    if (strcmp(argv[i], "--verbose") == 0)
    {
      *verbose = 1;
    }
    else if (strncmp(argv[i], "--output=", 9) == 0)
    {
      const char *filename = argv[i] + 9;
      if (filename[0] == '\0')
      {
        printf("Error: --output= requires a filename\n");
        exit(1);
      }
      *output_file = (char *)filename;
    }
    else
    {
      fprintf(stderr, "Warning: unknown option '%s'\n", argv[i]);
      // write(STDERR_FILENO, buf, len);
    }
  }

  fprintf(stderr, "Log analyser | Dir: %s | Processes: %d | Mode: %s | Verbose: %s | Output: %s\n\n",
          log_dir, *num_processes, argv[3],
          *verbose ? "yes" : "no",
          *output_file ? *output_file : "stdout");
  // write(STDERR_FILENO, buf, len);
}

void record_and_print_event(ClassifiedEvent *event, int *matched_events, int *type_of_event, int *severity_counts, int event_type, AnalysisMode mode)
{
  (*matched_events)++;
  type_of_event[event_type]++;
  severity_counts[event->severity]++;
  if (event_matches_mode(event, mode))
  {
    print_event(event, mode);
  }
}

void analyse_log(const char *line, int *matched_events, int *type_of_event, int *severity_counts, AnalysisMode mode)
{
  ClassifiedEvent event;
  ApacheLogEntry apache_entry;
  JSONLogEntry json_entry;
  SyslogEntry syslog_entry;
  // NginxErrorEntry nginx_entry;

  if (parse_apache_log(line, &apache_entry) == 0)
  {
    classify_apache_event(&apache_entry, &event);
    record_and_print_event(&event, matched_events, type_of_event, severity_counts, 0, mode);
  }
  else if (parse_json_log(line, &json_entry) == 0)
  {
    classify_json_event(&json_entry, &event);
    record_and_print_event(&event, matched_events, type_of_event, severity_counts, 3, mode);
  }
  else if (parse_syslog(line, &syslog_entry) == 0)
  {
    classify_syslog_event(&syslog_entry, &event);
    record_and_print_event(&event, matched_events, type_of_event, severity_counts, 1, mode);
  }
  // TO DO: add nginx error log parsing
  // else if (parse_nginx_error(line, &nginx_entry) == 0)
  // {
  //   classify_nginx_event(&nginx_entry, &event);
  //   record_and_print_event(&event, matched_events, type_of_event, severity_counts, 2, mode);
  // }
  else
  {
    type_of_event[4]++;
  }
}

void analyse_log_stream(int source_fd, int *total_lines, int *matched_events, int *type_of_event, int *severity_counts, AnalysisMode mode)
{
  char read_buffer[4096];
  char current_line[4096];
  ssize_t bytes_read = 0;
  unsigned int line_length = 0;

  while ((bytes_read = read(source_fd, read_buffer, sizeof(read_buffer))) > 0)
  {
    // Process each character in the buffer and build lines
    for (int buffer_index = 0; buffer_index < bytes_read; buffer_index++)
    {
      char current_char = read_buffer[buffer_index];
      current_line[line_length++] = current_char;

      // When a line is complete
      if (current_char == '\n' || line_length >= sizeof(current_line) - 1)
      {
        current_line[line_length] = '\0'; // Null-terminate to create a valid C-string
        (*total_lines)++;

        analyse_log(current_line, matched_events, type_of_event, severity_counts, mode);

        line_length = 0;
      }
    }
  }

  // safety measure: in case there is a line that doesn't end with '\n'
  if (line_length > 0)
  {
    current_line[line_length] = '\0';
    (*total_lines)++;
    analyse_log(current_line, matched_events, type_of_event, severity_counts, mode);
  }
}

void print_summary(int total_lines, int matched_events, int *type_of_event, int *severity_counts)
{

  printf("\n");
  printf("========================================\n");
  printf("SUMMARY\n");
  printf("========================================\n");
  printf("Total lines:      %d\n", total_lines);
  printf("Relevant events:  %d\n", matched_events);
  printf("\n");
  printf("By severity:\n");
  printf("  CRITICAL: %d\n", severity_counts[4]);
  printf("  HIGH:     %d\n", severity_counts[3]);
  printf("  MEDIUM:   %d\n", severity_counts[2]);
  printf("  LOW:      %d\n", severity_counts[1]);
  printf("  INFO:     %d\n", severity_counts[0]);
  printf("\n");
  printf("========================================\n");
  printf("By type:\n");
  printf("  Apache: %d\n", type_of_event[0]);
  printf("  Syslog: %d\n", type_of_event[1]);
  // printf("  Nginx:  %d\n", type_of_event[2]);
  printf("  JSON:   %d\n", type_of_event[3]);
  printf("  Unknown: %d\n", type_of_event[4]);
}

void process_directory_recursive(const char *dir_path, int *total_lines, int *matched_events, int *type_of_event, int *severity_counts, AnalysisMode mode)
{
  DIR *dir = opendir(dir_path);
  if (dir == NULL)
  {
    perror("Error opening directory");
    return;
  }

  struct dirent *entry;

  while ((entry = readdir(dir)) != NULL)
  {
    // Skip the "." (current directory) and ".." (parent directory) loops
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
    {
      continue;
    }

    // Construct the full path: "directory/filename"
    char next_path[4096];
    snprintf(next_path, sizeof(next_path), "%s/%s", dir_path, entry->d_name);

    struct stat path_stat;
    if (stat(next_path, &path_stat) != 0)
    {
      continue;
    }

    // If it's a directory, recurse into it
    if (S_ISDIR(path_stat.st_mode))
    {
      process_directory_recursive(next_path, total_lines, matched_events, type_of_event, severity_counts, mode);
    }
    // If it's a file, check if it ends with ".log"
    else if (S_ISREG(path_stat.st_mode))
    {
      size_t len = strlen(entry->d_name);
      if ((len > 4 && strcmp(entry->d_name + len - 4, ".log") == 0) ||
          (len > 5 && strcmp(entry->d_name + len - 5, ".json") == 0))
      {

        printf("Analyzing file %s in mode: %s\n\n", next_path, get_mode_name(mode));
        int source_fd = open(next_path, O_RDONLY);
        if (source_fd != -1)
        {
          analyse_log_stream(source_fd, total_lines, matched_events, type_of_event, severity_counts, mode);
          close(source_fd);
        }
        else
        {
          perror("Warning: Could not open file");
        }
      }
    }
  }

  closedir(dir);
}

int main(int argc, char *argv[])
{
  AnalysisMode mode = MODE_FULL;
  char input_directory[4096];
  char *output_file = NULL;
  int num_processes, verbose;
  int total_lines = 0;
  int matched_events = 0;
  int severity_counts[5] = {0}; // 5 levels of severity: INFO, LOW, MEDIUM, HIGH, CRITICAL
  int type_of_event[5] = {0};   // 5 types: Apache, Syslog, Nginx, JSON, Unknown

  parse_options(argc, argv, input_directory, &num_processes, &mode, &verbose, &output_file);

  process_directory_recursive(input_directory, &total_lines, &matched_events, type_of_event, severity_counts, mode);

  print_summary(total_lines, matched_events, type_of_event, severity_counts);

  return 0;
}