#!/usr/bin/env bash

set -euo pipefail

get_mem_available_kb() {
    grep MemAvailable /proc/meminfo | awk '{print $2}'
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
}

main() {
    local target="${1:-code-editor-sagemaker-server}"
    
    local build_target_base=$("$(dirname "$0")/determine-build-target.sh" "$target")
    echo "Building for target: $build_target_base"
    build "$build_target_base"
}

main "$@"
