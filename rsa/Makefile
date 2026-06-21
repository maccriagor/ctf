# Define phony targets to prevent conflicts with files of the same name
.PHONY: all clean build_pqc run_pqc extract_app run_runner

# The default target that runs everything in order
all: file.txt input.txt build_pqc run_pqc extract_app run_runner

# 1. Create file.txt with random content
file.txt:
	@echo "Creating file.txt "
	@echo "Loren ipusm... Just kidding. Here is some actual random data:" > file.txt
	@head -c 500 /dev/urandom | base64 >> file.txt

# 2. Create input.txt with 1000 on row 1, followed by 1MB of data
input.txt:
	@echo "Creating input.txt "
	@echo "1000" > input.txt
	@head -c 1048576 /dev/urandom | base64 | head -c 1048576 >> input.txt

# 3. Build the PQC Docker image
build_pqc:
	docker build -t pqc-app .

# 4. Run the PQC app with indicated output section
run_pqc: file.txt
	@echo ""
	@echo "=================================================="
	@echo "               TEST RUN            "
	@echo "=================================================="
	docker run --rm -i pqc-app < file.txt
	@echo "=================================================="
	@echo ""

# 5. Build, create, copy artifact, and cleanup temp container
extract_app:
	docker build -t my-app .
	@# Optional: remove existing 'temp' container if a previous run crashed
	-@docker rm -f temp >/dev/null 2>&1 || true
	docker create --name temp my-app
	docker cp temp:/app/app ./app
	docker rm temp

# 6. Run the python runner script
run_runner:
	python3 runner.py

# Clean up generated files if you want to start fresh
clean:
	rm -f file.txt input.txt ./app
