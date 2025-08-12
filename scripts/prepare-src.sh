#!/usr/bin/env bash

set -euo pipefail

PRESENT_WORKING_DIR="$(pwd)"
PATCHED_SRC_DIR="$PRESENT_WORKING_DIR/code-editor-src"
# Manually update this list to include all files for which there are modified script-src CSP rules
UPDATE_CHECKSUM_FILEPATHS=(
    "/src/vs/workbench/contrib/webview/browser/pre/index.html"
    "/src/vs/workbench/contrib/webview/browser/pre/index-no-csp.html"
    "/src/vs/workbench/services/extensions/worker/webWorkerExtensionHostIframe.html"
)

calc_script_SHAs() {
    local filepath="$1"
    
    if [[ ! -f "$filepath" ]]; then
        return 1
    fi
    
    # Get count of </script> elements to ensure we only handle single scripts
    local script_count
    script_count=$(xmllint --html --xpath "count(//script)" "$filepath" 2>/dev/null || echo "0")
    
    # Only process if there's exactly one script tag
    if [[ "$script_count" != "1" ]]; then
        if [[ "$script_count" == "0" ]]; then
            echo "No script tags found"
        else
            echo "Multiple script tags found ($script_count). Only single script updates are supported."
        fi
        return 0
    fi
    
    # Extract the single script content. Suppress HTML parsing warnings by re-directing error output to null.
    local script_content
    script_content=$(xmllint --html --xpath "//script[1]/text()" "$filepath" 2>/dev/null || true)
    
    # Remove CDATA markers if present. CDATA markers are added automatically by xmllint.
    if [[ "$script_content" == *"<![CDATA["* ]]; then
        # Strip CDATA opening and closing markers
        script_content="${script_content#*<![CDATA[}"
        script_content="${script_content%]]>*}"
    fi
    
    if [[ -z "$script_content" ]]; then
        echo "Script tag found but no content"
        return 0
    fi
    
    # Calculate SHA256 hash and encode to base64
    local hash=$(printf '%s' "$script_content" | openssl dgst -sha256 -binary | base64)
    local new_sha="'sha256-$hash'"
    
    # Update the file by replacing existing sha256 hash in CSP
    if grep -q "'sha256-[^']*'" "$filepath"; then
        # Use a more portable sed approach
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            sed -i '' "s|'sha256-[^']*'|$new_sha|g" "$filepath"
        else
            # Linux
            sed -i "s|'sha256-[^']*'|$new_sha|g" "$filepath"
        fi
        echo "Updated SHA in $filepath"
    fi
    
    # Print the result
    echo "$new_sha"
    return 0
}

apply_changes() {
    echo "Creating patched source in directory: ${PATCHED_SRC_DIR}"

    patch_dir="${PRESENT_WORKING_DIR}/patches"
    echo "Set patch directory as: $patch_dir"

    export QUILT_PATCHES="${patch_dir}"
    export QUILT_SERIES="${PRESENT_WORKING_DIR}/patches/sagemaker.series"

    # Clean out the build directory
    echo "Cleaning build src dir"
    rm -rf "${PATCHED_SRC_DIR}"

    # Copy third party source
    echo "Copying third party source to the patch directory"
    rsync -a "${PRESENT_WORKING_DIR}/third-party-src/" "${PATCHED_SRC_DIR}"

    echo "Applying base patches"
    pushd "${PATCHED_SRC_DIR}"
    quilt push -a
    popd

    echo "Applying overrides"
    rsync -a "${PRESENT_WORKING_DIR}/overrides/" "${PATCHED_SRC_DIR}"

    echo "Applying package-lock overrides"
    rsync -a "${PRESENT_WORKING_DIR}/package-lock-overrides/sagemaker.series/" "${PATCHED_SRC_DIR}"
}

update_inline_sha() {
    echo "Running calculate SHA script"

    if [[ ! -d "${PATCHED_SRC_DIR}" ]]; then
        echo "Error: PATCHED_SRC_DIR (${PATCHED_SRC_DIR}) does not exist. Run apply_changes first."
        return 1
    fi
    
    for file_path in "${UPDATE_CHECKSUM_FILEPATHS[@]}"; do
        local full_path="$PATCHED_SRC_DIR$file_path"
        local sha_result
        
        if [[ -f "$full_path" ]]; then
            echo -n "$file_path: "
            sha_result=$(calc_script_SHAs "$full_path")
            echo "$sha_result"
        else
            echo "$file_path: not found"
        fi
    done
}

apply_changes
update_inline_sha