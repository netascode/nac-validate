#!/bin/bash
# Script to check or fix SPDX license identifier and copyright notice in Python files
#
# Usage:
#   ./scripts/license-headers.sh                    # Check all git-tracked Python files
#   ./scripts/license-headers.sh --fix              # Fix mode (add missing headers)
#   ./scripts/license-headers.sh [FILES...]         # Check specific files
#   ./scripts/license-headers.sh --fix [FILES...]   # Fix specific files
#   ./scripts/license-headers.sh --help             # Show help
#
# When called without file arguments, uses 'git ls-files' to find all tracked Python files.
# When called with file arguments (e.g., from pre-commit), only checks those files.

set -euo pipefail

# Temporary file management with cleanup trap
TEMP_FILE=""
cleanup() {
    local exit_code=$?
    if [[ -n "${TEMP_FILE:-}" && -f "$TEMP_FILE" ]]; then
        rm -f "$TEMP_FILE"
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Configuration
EXPECTED_SPDX="# SPDX-License-Identifier: MPL-2.0"
EXPECTED_COPYRIGHT="# Copyright (c) 2025 Daniel Schmidt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
MODE="check"
FILES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fix)
            MODE="fix"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [FILES...]"
            echo ""
            echo "Check or fix SPDX license headers in Python files."
            echo ""
            echo "Options:"
            echo "  (none)      Check mode - verify headers are present and correct (exit 1 if issues found)"
            echo "  --fix       Fix mode - add missing headers to files"
            echo "  --help, -h  Show this help message"
            echo ""
            echo "Arguments:"
            echo "  FILES       Optional list of files to check. If not provided, checks all"
            echo "              git-tracked Python files (via 'git ls-files')."
            echo ""
            echo "Examples:"
            echo "  $0                        # Check all git-tracked Python files"
            echo "  $0 --fix                  # Add headers to all files missing them"
            echo "  $0 src/main.py src/util.py   # Check specific files"
            echo "  $0 --fix src/main.py      # Fix specific file"
            exit 0
            ;;
        *)
            FILES+=("$1")
            shift
            ;;
    esac
done

# Counters
files_checked=0
files_skipped=0
files_failed=0
files_fixed=0

# Array to store files with issues (check mode only)
declare -a failed_files

# Validate file before processing
validate_file() {
    local file="$1"
    [[ -f "$file" ]] || { echo "ERROR: Not a regular file: $file" >&2; return 1; }
    [[ -r "$file" ]] || { echo "ERROR: File not readable: $file" >&2; return 1; }
    [[ ! -L "$file" ]] || { echo "ERROR: Refusing symlink: $file" >&2; return 1; }
    [[ -w "$file" ]] || { echo "ERROR: File not writable: $file" >&2; return 1; }
    return 0
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
    TEMP_FILE=$(mktemp)
    local first_line=$(head -n 1 "$file")

    if [[ "$first_line" == "#!"* ]]; then
        # Preserve shebang, add headers after it
        echo "$first_line" > "$TEMP_FILE"
        echo "$EXPECTED_SPDX" >> "$TEMP_FILE"
        echo "$EXPECTED_COPYRIGHT" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
        tail -n +2 "$file" >> "$TEMP_FILE"
    else
        # No shebang, add headers at the top
        echo "$EXPECTED_SPDX" > "$TEMP_FILE"
        echo "$EXPECTED_COPYRIGHT" >> "$TEMP_FILE"
        echo "" >> "$TEMP_FILE"
        cat "$file" >> "$TEMP_FILE"
    fi

    mv "$TEMP_FILE" "$file"
    TEMP_FILE=""
}

# Print header based on mode
if [[ "$MODE" == "check" ]]; then
    echo -e "${BLUE}Checking Python file headers...${NC}"
else
    echo -e "${BLUE}Adding headers to Python files...${NC}"
fi
echo ""

# Get list of files to process
if [[ ${#FILES[@]} -gt 0 ]]; then
    # Files passed as arguments (e.g., from pre-commit)
    file_list=("${FILES[@]}")
else
    # No files specified, get all git-tracked Python files
    file_list=()
    while IFS= read -r f; do
        file_list+=("$f")
    done < <(git ls-files '*.py')
fi

# Process each file
for file in "${file_list[@]}"; do
    # Validate file first
    if ! validate_file "$file"; then
        files_failed=$((files_failed + 1))
        failed_files+=("$file")
        continue
    fi

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
            if add_headers "$file"; then
                echo -e "${GREEN}✓${NC} $file (header added)"
                files_fixed=$((files_fixed + 1))
            else
                echo -e "${RED}✗${NC} $file (FAILED to add header)" >&2
                files_failed=$((files_failed + 1))
                failed_files+=("$file")
            fi
        fi
    fi
done

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
    if [ $files_failed -gt 0 ]; then
        echo -e "${RED}Files failed: $files_failed${NC}"
    fi
    echo ""
    if [ $files_failed -gt 0 ]; then
        echo -e "${RED}✗ Some files could not be processed:${NC}"
        for file in "${failed_files[@]}"; do
            echo "  - $file"
        done
        exit 1
    elif [ $files_fixed -eq 0 ]; then
        echo -e "${GREEN}✓ All files already had correct headers!${NC}"
    else
        echo -e "${GREEN}✓ Header addition complete!${NC}"
    fi
    exit 0
fi
