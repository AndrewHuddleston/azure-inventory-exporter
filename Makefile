# Makefile for Azure Inventory Exporter
# Usage:
#   make clean  - Remove all generated CSV files

.PHONY: clean help

help:
	@echo "Azure Inventory Exporter - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make clean    - Remove all generated CSV files"
	@echo "  make help     - Show this help message"

clean:
	@echo "Removing all CSV files..."
	@rm -f *.csv
	@echo "CSV files removed."
