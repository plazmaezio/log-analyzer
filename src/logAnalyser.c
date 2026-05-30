// No Nginx parser used
#include "log_parser.h"
#include "event_classifier.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <dirent.h>
#include <sys/stat.h>

#define COLOR_RED "\033[0;31m"
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_BLUE "\033[0;34m"
#define COLOR_RESET "\033[0m"

typedef struct
{
  int total_lines;
  int matched_events;
  int severity_counts[5];
  int type_of_event[5];
  pthread_mutex_t lock;
} SharedResults;
void init_shared_results(SharedResults *results)
{
  results->total_lines = 0;
  results->matched_events = 0;
  memset(results->severity_counts, 0, sizeof(results->severity_counts));
  memset(results->type_of_event, 0, sizeof(results->type_of_event));
  pthread_mutex_init(&results->lock, NULL);
}

void destroy_shared_results(SharedResults *results)
{
  pthread_mutex_destroy(&results->lock);
}

// Helper functions for printing and mode handling

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

// Main analysis functions

int collect_log_files(const char *dir_path, char files[][512], int max_files)
{
  DIR *dir = opendir(dir_path);
  if (dir == NULL)
  {
    perror("Error opening directory");
    return 0;
  }

  int count = 0;
  struct dirent *entry;

  while ((entry = readdir(dir)) != NULL && count < max_files)
  {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    char next_path[512];
    snprintf(next_path, sizeof(next_path), "%s/%s", dir_path, entry->d_name);

    struct stat path_stat;
    if (stat(next_path, &path_stat) != 0)
      continue;

    if (S_ISDIR(path_stat.st_mode))
    {
      count += collect_log_files(next_path, files + count, max_files - count);
    }
    else if (S_ISREG(path_stat.st_mode))
    {
      size_t len = strlen(entry->d_name);
      if ((len > 4 && strcmp(entry->d_name + len - 4, ".log") == 0) ||
          (len > 5 && strcmp(entry->d_name + len - 5, ".json") == 0))
      {
        snprintf(files[count], sizeof(files[count]), "%s", next_path);
        count++;
      }
    }
  }

  closedir(dir);
  return count;
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

int main(int argc, char *argv[])
{
  AnalysisMode mode = 0;
  char input_directory[512], *output_file;
  int num_processes, verbose;

  parse_options(argc, argv, input_directory, &num_processes, &mode, &verbose, &output_file);

  // Collect all log files from directory
  char files[1024][512];
  int file_count = collect_log_files(input_directory, files, 1024);

  if (file_count == 0)
  {
    fprintf(stderr, "No log files found in %s\n", input_directory);
    return 1;
  }

  fprintf(stderr, "Found %d log file(s)\n", file_count);

  SharedResults results;
  init_shared_results(&results);

  // ... thread work goes here ...

  print_summary(results.total_lines, results.matched_events, results.type_of_event, results.severity_counts);

  destroy_shared_results(&results);

  return 0;
}