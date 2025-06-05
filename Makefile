# Makefile for FTP-Lite

HOST=0.0.0.0
PORT=4444
CERT=cert.pem
KEY=key.pem

.PHONY: all run server client test clean

all: run

run:
	@echo "Running tests..."
	./run.sh

server:
	@echo "Starting FTP-Lite server..."
	./run_server.sh $(HOST) $(PORT) $(CERT) $(KEY)

client:
	@echo "Starting client upload..."
	python3 client.py 127.0.0.1 myfile.txt --user bob --pass admin --port $(PORT) --cert $(CERT)

test:
	@echo "Running Pytest suite..."
	pytest tests/test_ftplite.py

clean:
	@echo "Cleaning up..."
	rm -rf __pycache__ Result/*.txt *.pyc

