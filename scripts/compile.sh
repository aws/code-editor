#!/usr/bin/env bash

set -euo pipefail

# Function to get available memory in KB
get_mem_available_kb() {
    grep MemAvailable /proc/meminfo | awk '{print $2}'
}

# Function to determine build target
determine_build_target() {
    local target="$1"
    local arch=$(uname -m)
    
    case "$target" in
        "code-editor-server"|"code-editor-sagemaker-server")
            echo "vscode-reh-web-linux-${arch}"
            ;;
        "code-editor-web-embedded"|"code-editor-web-embedded-with-terminal")
            echo "vscode-web"
            ;;
        *)
            echo "Error: Unknown target: $target" >&2
            exit 1
            ;;
    esac
}

# Main build function
build() {
    local code_oss_build_target_base="$1"
    
    # Calculate memory allocation
    local mem_available_kb=$(get_mem_available_kb)
    local max_space_size_mb=$((mem_available_kb / 1024 - 2048))
    if [ $max_space_size_mb -lt 8192 ]; then
        max_space_size_mb=8192
    fi
    
    # Set up paths
    local present_working_dir="$(pwd)"
    local build_src_dir="${present_working_dir}/code-editor-src"
    
    # Determine build target (always prod, so always use -min)
    local build_target="${code_oss_build_target_base}-min"
    
    echo "Building Code Editor with '$build_target' as target with ${max_space_size_mb} MiB allocated heap"
    
    # Execute the build
    cd "$build_src_dir"
    
    env \
        NODE_OPTIONS="--max-old-space-size=${max_space_size_mb}" \
        npm run gulp "$build_target"
}

# Main execution
main() {
    local target="${1:-code-editor-sagemaker-server}"
    
    local build_target_base=$(determine_build_target "$target")
    build "$build_target_base"
}

main "$@"