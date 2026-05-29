# Makefile for the Log analyser project (Linux/macOS compatible)

CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.

# Detect operating system
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LDFLAGS = -lrt -pthread
endif
ifeq ($(UNAME_S),Darwin)
    LDFLAGS = -pthread
endif

# Files
PARSER_SRC = log_parser.c
PARSER_OBJ = log_parser.o
EVENT_SRC = event_classifier.c
EVENT_OBJ = event_classifier.o

TEST_SRC = test_parsers.c
TEST_BIN = test_parsers
CLASSIFIER_SRC = test_classifier.c
CLASSIFIER_BIN = test_classifier

ANALYSER_SRC = logAnalyser.c
ANALYSER_BIN = logAnalyser

# Generators
GEN_DIR = ../generators
GEN_APACHE = $(GEN_DIR)/gen_apache
GEN_JSON = $(GEN_DIR)/gen_json
GEN_SYSLOG = $(GEN_DIR)/gen_syslog
GEN_NGINX = $(GEN_DIR)/gen_nginx

# Datasets
DATASET_DIR = ../datasets
APACHE_DIR = $(DATASET_DIR)/apache
JSON_DIR = $(DATASET_DIR)/json_logs
SYSLOG_DIR = $(DATASET_DIR)/syslog
NGINX_DIR = $(DATASET_DIR)/nginx

.PHONY: all clean test generators datasets help

all: classifier test generators

# Compile Classifier
classifier: $(CLASSIFIER_BIN)

$(CLASSIFIER_BIN): $(CLASSIFIER_SRC) $(PARSER_OBJ) $(EVENT_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Classifier compiled: ./$(CLASSIFIER_BIN)"

# Compile tests
test: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(PARSER_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ Test suite compiled: ./$(TEST_BIN)"

$(PARSER_OBJ): $(PARSER_SRC)
	$(CC) $(CFLAGS) -c $< -o $@
	
$(EVENT_OBJ): $(EVENT_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# Compile generators
generators: $(GEN_APACHE) $(GEN_JSON) $(GEN_SYSLOG) $(GEN_NGINX)

$(GEN_APACHE): $(GEN_DIR)/generate_apache_logs.c
	$(CC) -O2 $< -o $@
	@echo "✓ Apache generator compiled"

$(GEN_JSON): $(GEN_DIR)/generate_json_logs.c
	$(CC) -O2 $< -o $@
	@echo "✓ JSON generator compiled"

$(GEN_SYSLOG): $(GEN_DIR)/generate_syslog.c
	$(CC) -O2 $< -o $@
	@echo "✓ Syslog generator compiled"

$(GEN_NGINX): $(GEN_DIR)/generate_nginx_error.c
	$(CC) -O2 $< -o $@
	@echo "✓ Nginx generator compiled"

# Generate datasets
datasets: generators
	@echo "Generating test datasets..."
	@mkdir -p $(APACHE_DIR) $(JSON_DIR) $(SYSLOG_DIR) $(NGINX_DIR)
	@./$(GEN_APACHE) 1000 > $(APACHE_DIR)/sample_1k.log 2>&1
	@echo "  ✓ Apache: 1K lines generated"
	@./$(GEN_JSON) 500 50 $(JSON_DIR)/ 2>&1
	@echo "  ✓ JSON: 500 lines across 50 files"
	@./$(GEN_SYSLOG) 500 > $(SYSLOG_DIR)/sample_500.log 2>&1
	@echo "  ✓ Syslog: 500 lines generated"
	@./$(GEN_NGINX) 300 > $(NGINX_DIR)/sample_300.log 2>&1
	@echo "  ✓ Nginx: 300 lines generated"
	@echo ""
	@echo "Datasets created:"
	@du -sh $(DATASET_DIR)/*

# Generate large datasets
datasets-large: generators
	@echo "Generating LARGE datasets (this may take a while)..."
	@mkdir -p $(APACHE_DIR) $(JSON_DIR) $(SYSLOG_DIR) $(NGINX_DIR)
	@./$(GEN_APACHE) 100000 > $(APACHE_DIR)/access_100k.log 2>&1
	@echo "  ✓ Apache: 100K lines (~10 MB)"
	@./$(GEN_JSON) 50000 500 $(JSON_DIR)/ 2>&1
	@echo "  ✓ JSON: 50K lines across 500 files"
	@./$(GEN_SYSLOG) 50000 > $(SYSLOG_DIR)/security_50k.log 2>&1
	@echo "  ✓ Syslog: 50K lines (~2 MB)"
	@./$(GEN_NGINX) 20000 > $(NGINX_DIR)/error_20k.log 2>&1
	@echo "  ✓ Nginx: 20K lines (~1 MB)"
	@echo ""
	@du -sh $(DATASET_DIR)/*

# Run tests
run-tests: test datasets
	@echo ""
	@echo "Running test suite..."
	@echo ""
	@./$(TEST_BIN)

# Clean compiled files
clean:
	rm -f $(PARSER_OBJ)
	rm -f $(EVENT_OBJ)
	rm -f $(TEST_BIN)
	rm -f $(CLASSIFIER_BIN)
	rm -f $(GEN_APACHE) $(GEN_JSON) $(GEN_SYSLOG) $(GEN_NGINX)
	rm -f $(APACHE_DIR)/*
	rm -f $(JSON_DIR)/*
	rm -f $(SYSLOG_DIR)/*
	rm -f $(NGINX_DIR)/*
	
	@echo "✓ Compiled files removed"

# Clean everything including datasets
clean-all: clean
	rm -rf $(DATASET_DIR)
	@echo "✓ Datasets removed"

# Help
help:
	@echo "Makefile - Log analyser Project"
	@echo ""
	@echo "Detected system: $(UNAME_S)"
	@echo ""
	@echo "Available targets:"
	@echo "  make               - Compiles tests, log generators, and event classifier"
	@echo "  make test          - Compiles only the tests"
	@echo "  make generators    - Compiles log generators"
	@echo "  make classifier    - Compiles the event classifier"
	@echo "  make datasets      - Generates small datasets (~1MB)"
	@echo "  make datasets-large- Generates large datasets (~15MB)"
	@echo "  make run-tests     - Compiles and runs tests"
	@echo "  make clean         - Removes compiled files"
	@echo "  make clean-all     - Removes everything (including datasets)"
	@echo "  make help          - Shows this help message"
	@echo ""
	@echo "Typical usage:"
	@echo "  1. make              # Compile everything"
	@echo "  2. make datasets     # Generate data"
	@echo "  3. make run-tests    # Test"
	

# Compile analyser (main program)
analyser: $(ANALYSER_BIN)

$(ANALYSER_BIN): $(ANALYSER_SRC) $(PARSER_OBJ) $(EVENT_OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	@echo "✓ analyser compiled: ./$(ANALYSER_BIN)"