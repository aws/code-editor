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
    if [ -f "$config_file" ]; then
        local ignored_errors_path=$(jq -r '.ignoredErrors.path' "$config_file")
        local ignored_errors_file="$present_working_dir/$ignored_errors_path/common-ignored-errors.json"
        
        if [ -f "$ignored_errors_file" ]; then
            local build_dir="$(pwd)/$build_target_base/out/vs/editor/common/errors"
            
            echo "Copying ignored errors to $build_dir"
            
            # Strip comments and parse JSON
            local clean_json=$(sed 's|//.*$||g' "$ignored_errors_file" | sed '/\/\*/,/\*\//d')
            local string_count=$(echo "$clean_json" | jq '.stringPatterns | length')
            local regex_count=$(echo "$clean_json" | jq '.regexPatterns | length')
            
            echo "Number of string ignored errors: $string_count"
            echo "Number of regex ignored errors: $regex_count"
            echo "Writing ignored errors to $build_dir"
            
            mkdir -p "$build_dir"
            echo "$clean_json" | jq '.' > "$build_dir/ignored-errors.json"
        else
            echo "Ignored errors file not found: $ignored_errors_file"
        fi
    else
        echo "Config file not found: $config_file"
    fi
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