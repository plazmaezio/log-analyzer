// No Nginx parser used
#include "log_parser.h"
#include "event_classifier.h"
#include <stdio.h>
#include <unistd.h>

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

static void parse_options(int argc, char *argv[],
                          char **log_dir,
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
  *log_dir = argv[1];
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
          *log_dir, *num_processes, argv[3],
          *verbose ? "yes" : "no",
          *output_file ? *output_file : "stdout");
  // write(STDERR_FILENO, buf, len);
}

int main(int argc, char *argv[])
{

  char *input_filename, *output_file;
  AnalysisMode mode;
  int num_processes, verbose;
  parse_options(argc, argv, &input_filename, &num_processes, &mode, &verbose, &output_file);

  // Determinar modo
  //  assign_analysis_mode(mode_str, &mode);
  // printf("Analyzing file %s in mode: %s\n\n", input_filename, get_mode_name(mode));

  // change to more rudimentary file reading

  printf("Analyzing file %s in mode: %s\n\n", input_filename, get_mode_name(mode));
  FILE *fp = fopen(input_filename, "r");
  if (!fp)
  {
    perror("fopen");
    return 1;
  }

  char line[4096];
  int total_lines = 0;
  int matched_events = 0;

  // 5 levels of severity: INFO, LOW, MEDIUM, HIGH, CRITICAL
  int severity_counts[5] = {0};
  int type_of_event[5] = {0};
  // GET LINE BY LINE AND CLASSIFY
  while (fgets(line, sizeof(line), fp))
  {
    // fprintf(stdout, "Processing line %s...\n", line);
    total_lines++;

    ClassifiedEvent event;

    // Attempt to match to apache
    ApacheLogEntry apache_entry;
    if (parse_apache_log(line, &apache_entry) == 0)
    {
      classify_apache_event(&apache_entry, &event);
      matched_events++;
      type_of_event[0]++;
      severity_counts[event.severity]++;
      if (event_matches_mode(&event, mode))
      {
        print_event(&event, mode);
      }
      continue;
    }

    /* TO DO: Add Nginx parser and classifier and uncomment this block
    NginxErrorEntry nginx_entry;
    if (parse_nginx_error(line, &nginx_entry) == 0) {
        printf("Matched Nginx\n");
        classify_nginx_event(&nginx_entry, &event);
        if(event_matches_mode(&event, mode)) {
            print_event(&event, mode);
            matched_events++;
            type_of_event[2]++;
            severity_counts[event.severity]++;
        }
        continue;
    }
    printf("Not Nginx\n");
    */
    JSONLogEntry json_entry;
    if (parse_json_log(line, &json_entry) == 0)
    {
      classify_json_event(&json_entry, &event);
      matched_events++;
      type_of_event[3]++;
      severity_counts[event.severity]++;
      if (event_matches_mode(&event, mode))
      {
        print_event(&event, mode);
      }
      continue;
    }
    // Attempt to match to Syslog
    SyslogEntry syslog_entry;
    if (parse_syslog(line, &syslog_entry) == 0)
    {
      classify_syslog_event(&syslog_entry, &event);
      matched_events++;
      type_of_event[1]++;
      severity_counts[event.severity]++;
      if (event_matches_mode(&event, mode))
      {
        print_event(&event, mode);
      }
      continue;
    }

    type_of_event[4]++;
  }

  fclose(fp);

  // Sumário
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

  return 0;
}