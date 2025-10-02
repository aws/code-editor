#!/usr/bin/env bash

set -euo pipefail

get_mem_available_kb() {
    grep MemAvailable /proc/meminfo | awk '{print $2}'
}

copy_ignored_errors() {
    local build_target_base="$1"
    local target="$2"
    
    local present_working_dir="$(pwd)"
    local config_file="$present_working_dir/configuration/$target.json"
    local build_dir="$(pwd)/$build_target_base/out/vs/editor/common/errors"
    local output_file="$build_dir/ignored-errors.json"
    
    echo "Processing ignored errors for target: $target"
    mkdir -p "$build_dir"
    
    # Step 1: Collect all .json files from common-ignored-errors directory
    local common_files=()
    if [[ -d "${present_working_dir}/common-ignored-errors" ]]; then
        echo "Step 1: Looking for common ignored errors files"
        while IFS= read -r -d '' file; do
            common_files+=("$file")
            echo "  Found: $(basename "$file")"
        done < <(find "${present_working_dir}/common-ignored-errors" -name "*.json" -print0 2>/dev/null || true)
    fi
    
    # Step 2: Collect target-specific .json files if path is not null
    local target_files=()
    if [ -f "$config_file" ]; then
        local ignored_errors_path=$(jq -r '.ignoredErrors.path' "$config_file")
        if [[ "$ignored_errors_path" != "null" && -n "$ignored_errors_path" && -d "${present_working_dir}/$ignored_errors_path" ]]; then
            echo "Step 2: Looking for target-specific ignored errors files in: $ignored_errors_path"
            while IFS= read -r -d '' file; do
                target_files+=("$file")
                echo "  Found: $(basename "$file")"
            done < <(find "${present_working_dir}/$ignored_errors_path" -name "*.json" -print0 2>/dev/null || true)
        else
            echo "Step 2: Skipping target-specific files (path is null or doesn't exist)"
        fi
    else
        echo "Config file not found: $config_file"
    fi
    
    # Step 3: Merge all JSON files
    echo "Step 3: Merging all ignored errors files"
    local temp_file=$(mktemp)
    echo '{"stringPatterns": [], "regexPatterns": []}' > "$temp_file"
    
    # Function to clean JSON (remove comments)
    clean_and_merge() {
        local file="$1"
        local temp_clean=$(mktemp)
        # Remove single-line comments and multi-line comments
        sed 's|//.*$||g' "$file" | sed '/\/\*/,/\*\//d' > "$temp_clean"
        jq -s '.[0] as $base | .[1] as $new | $base + {stringPatterns: ($base.stringPatterns + ($new.stringPatterns // [])), regexPatterns: ($base.regexPatterns + ($new.regexPatterns // []))}' "$temp_file" "$temp_clean" > "${temp_file}.tmp" && mv "${temp_file}.tmp" "$temp_file"
        rm "$temp_clean"
    }
    
    # Merge common files
    if [[ ${#common_files[@]} -gt 0 ]]; then
        for file in "${common_files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "  Merging: $(basename "$file")"
                clean_and_merge "$file"
            fi
        done
    fi
    
    # Merge target-specific files
    if [[ ${#target_files[@]} -gt 0 ]]; then
        for file in "${target_files[@]}"; do
            if [[ -f "$file" ]]; then
                echo "  Merging: $(basename "$file")"
                clean_and_merge "$file"
            fi
        done
    fi
    
    # Copy merged result to output location
    cp "$temp_file" "$output_file"
    rm "$temp_file"
    
    # Report final counts
    local string_count=$(jq '.stringPatterns | length' "$output_file")
    local regex_count=$(jq '.regexPatterns | length' "$output_file")
    echo "Created ignored-errors.json with $string_count string patterns and $regex_count regex patterns"
    echo "Output written to: $output_file"
}

build() {
    local code_oss_build_target_base="$1"
    
    # Calculate memory allocation
    local mem_available_kb=$(get_mem_available_kb)
    local max_space_size_mb=$((mem_available_kb / 1024 - 2048))
    echo "Available memory: ${mem_available_kb} KiB = ${max_space_size_mb} MiB"
    if [ $max_space_size_mb -lt 8192 ]; then
        max_space_size_mb=8192
    fi
    
    # Set up paths
    local present_working_dir="$(pwd)"
    local build_src_dir="${present_working_dir}/code-editor-src"
    
    local build_target="${code_oss_build_target_base}-min"
    
    echo "Building Code Editor with '$build_target' as target with ${max_space_size_mb} MiB allocated heap"
    
    cd "$build_src_dir"
    env \
        NODE_OPTIONS="--max-old-space-size=${max_space_size_mb}" \
        npm run gulp "$build_target"
    cd ..
}

main() {
    local target="${1:-code-editor-sagemaker-server}"
    
    local build_target_base=$("$(dirname "$0")/determine-build-target.sh" "$target")
    echo "Building for target: $build_target_base"
    build "$build_target_base"
    copy_ignored_errors "$build_target_base" "$target"
}

main "$@"