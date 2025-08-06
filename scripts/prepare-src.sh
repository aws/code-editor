#!/usr/bin/env bash

set -euo pipefail

apply_changes() {
    local present_working_dir="$(pwd)"
    local patched_src_dir="$present_working_dir/code-editor-src"
    echo "Creating patched source in directory: ${patched_src_dir}"

    patch_dir="${present_working_dir}/patches"
    echo "Set patch directory as: $patch_dir"

    export QUILT_PATCHES="${patch_dir}"
    export QUILT_SERIES="${present_working_dir}/patches/sagemaker.series"

    # Clean out the build directory
    echo "Cleaning build src dir"
    rm -rf "${patched_src_dir}"

    # Copy third party source
    echo "Copying third party source to the patch directory"
    rsync -a "${present_working_dir}/third-party-src/" "${patched_src_dir}"

    echo "Applying base patches"
    pushd "${patched_src_dir}"
    quilt push -a
    popd

    echo "Applying overrides"
    rsync -a "${present_working_dir}/overrides/" "${patched_src_dir}"
}

apply_changes
