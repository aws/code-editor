#!/usr/bin/env bash

set -euo pipefail

apply_changes() {

    # Use custom path if provided, otherwise default to ./vscode
    local patched_src_dir="${1:-$(pwd)/vscode}"
    echo "Creating patched source in directory: ${patched_src_dir}"

    # code_editor_module_path="$(dirname "$(dirname "${BASH_SOURCE[0]}")")"
    # patch_dir="${code_editor_module_path}/patches"
    # echo "Code Editor module path: $code_editor_module_path"
    # echo "Patch directory: $patch_dir"

    export QUILT_PATCHES="${patch_dir}"
    export QUILT_SERIES="sagemaker.series"

    # Clean out the build directory
    echo "Cleaning build src dir"
    rm -rf "${patched_src_dir}"

    # Copy third party source
    rsync -a "third-party-src/" "${patched_src_dir}"

    echo "Applying base patches"
    pushd "${patched_src_dir}"
    quilt push -a
    popd

    echo "Applying overrides"
    rsync -a "overrides/" "${patched_src_dir}"

    echo "Zipping patched source"
    tar -chzvf "patched_source.tar.gz" $patched_src_dir
}

custom_path=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --path)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --path requires a value"
                exit 1
            fi
            custom_path="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--path <directory>]"
            echo "  --path: Custom build directory (default: ./vscode)"
            exit 0
            ;;
        *)
            echo "Invalid parameter - '$1'"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done
apply_changes "${custom_path}"