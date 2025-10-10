#!/bin/bash
# Script to check or fix SPDX license identifier and copyright notice in all Python files
#
# Usage:
#   ./scripts/license-headers.sh          # Check mode (default)
#   ./scripts/license-headers.sh --fix    # Fix mode (add missing headers)
#   ./scripts/license-headers.sh --help   # Show help

set -e

# Configuration
EXPECTED_SPDX="# SPDX-License-Identifier: MPL-2.0"
EXPECTED_COPYRIGHT="# Copyright (c) 2025 Daniel Schmidt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Mode selection
MODE="check"
if [[ "$1" == "--fix" ]]; then
    MODE="fix"
elif [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Check or fix SPDX license headers in Python files."
    echo ""
    echo "Options:"
    echo "  (none)      Check mode - verify headers are present and correct (exit 1 if issues found)"
    echo "  --fix       Fix mode - add missing headers to files"
    echo "  --help, -h  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0              # Check all Python files"
    echo "  $0 --fix        # Add headers to files missing them"
    exit 0
fi

# Counters
files_checked=0
files_skipped=0
files_failed=0
files_fixed=0

# Array to store files with issues (check mode only)
declare -a failed_files

# Common exclusion patterns
EXCLUDE_PATTERNS=(
    "./venv/*"
    "./.venv/*"
    "*/__pycache__/*"
    "./.tox/*"
    "./.eggs/*"
    "./build/*"
    "./dist/*"
    "./.pytest_cache/*"
    "./.mypy_cache/*"
)

# Build find command with exclusions
build_find_command() {
    local cmd="find . -name '*.py' -type f"
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        cmd="$cmd -not -path '$pattern'"
    done
    echo "$cmd"
}

# Check if file has correct headers
check_headers() {
    local file="$1"
    local first_line=$(head -n 1 "$file")
    local line_spdx line_copyright

    if [[ "$first_line" == "#!"* ]]; then
        # File has shebang, check lines 2 and 3
        line_spdx=$(sed -n '2p' "$file")
        line_copyright=$(sed -n '3p' "$file")
    else
        # No shebang, check lines 1 and 2
        line_spdx=$(sed -n '1p' "$file")
        line_copyright=$(sed -n '2p' "$file")
    fi

    if [[ "$line_spdx" == "$EXPECTED_SPDX" ]] && [[ "$line_copyright" == "$EXPECTED_COPYRIGHT" ]]; then
        return 0  # Headers are correct
    else
        return 1  # Headers are missing or incorrect
    fi
}

# Add headers to file
add_headers() {
    local file="$1"
    local temp_file=$(mktemp)
    local first_line=$(head -n 1 "$file")

    if [[ "$first_line" == "#!"* ]]; then
        # Preserve shebang, add headers after it
        echo "$first_line" > "$temp_file"
        echo "$EXPECTED_SPDX" >> "$temp_file"
        echo "$EXPECTED_COPYRIGHT" >> "$temp_file"
        echo "" >> "$temp_file"
        tail -n +2 "$file" >> "$temp_file"
    else
        # No shebang, add headers at the top
        echo "$EXPECTED_SPDX" > "$temp_file"
        echo "$EXPECTED_COPYRIGHT" >> "$temp_file"
        echo "" >> "$temp_file"
        cat "$file" >> "$temp_file"
    fi

    mv "$temp_file" "$file"
}

# Print header based on mode
if [[ "$MODE" == "check" ]]; then
    echo -e "${BLUE}Checking Python file headers...${NC}"
else
    echo -e "${BLUE}Adding headers to Python files...${NC}"
fi
echo ""

# Find all Python files and store in temp file
temp_file=$(mktemp)
eval "$(build_find_command)" > "$temp_file"

# Process each file
while IFS= read -r file; do
    # Skip empty files or files with only whitespace
    if [ ! -s "$file" ] || ! grep -q '[^[:space:]]' "$file"; then
        echo -e "${YELLOW}⊘${NC} $file (empty file, skipped)"
        files_skipped=$((files_skipped + 1))
        continue
    fi

    files_checked=$((files_checked + 1))

    if check_headers "$file"; then
        # Headers are correct
        if [[ "$MODE" == "fix" ]]; then
            echo -e "${GREEN}✓${NC} $file (already has header)"
        fi
    else
        # Headers are missing or incorrect
        if [[ "$MODE" == "check" ]]; then
            echo -e "${RED}✗${NC} $file (missing or incorrect header)"
            files_failed=$((files_failed + 1))
            failed_files+=("$file")
        else
            # Fix mode - add headers
            add_headers "$file"
            echo -e "${GREEN}✓${NC} $file (header added)"
            files_fixed=$((files_fixed + 1))
        fi
    fi
done < "$temp_file"

# Cleanup temp file
rm -f "$temp_file"

# Print summary
echo ""
echo "----------------------------------------"
echo "Files checked: $files_checked"
echo "Files skipped: $files_skipped"

if [[ "$MODE" == "check" ]]; then
    echo ""
    if [ $files_failed -eq 0 ]; then
        echo -e "${GREEN}✓ All Python files have correct headers!${NC}"
        exit 0
    else
        echo -e "${RED}✗ $files_failed file(s) missing or have incorrect headers${NC}"
        echo ""
        echo "Files needing fixes:"
        for file in "${failed_files[@]}"; do
            echo "  - $file"
        done
        echo ""
        echo "Run '$0 --fix' to automatically add headers"
        exit 1
    fi
else
    # Fix mode
    echo "Files fixed: $files_fixed"
    echo ""
    if [ $files_fixed -eq 0 ]; then
        echo -e "${GREEN}✓ All files already had correct headers!${NC}"
    else
        echo -e "${GREEN}✓ Header addition complete!${NC}"
    fi
    exit 0
fi
