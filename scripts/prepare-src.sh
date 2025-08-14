#!/usr/bin/env bash

set -euo pipefail

# Parse command line arguments
REBASE=false
TARGET="code-editor-sagemaker-server"

while [[ $# -gt 0 ]]; do
    case $1 in
        --rebase)
            REBASE=true
            shift
            ;;
        -*)
            echo "Unknown option $1" >&2
            exit 1
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

PRESENT_WORKING_DIR="$(pwd)"
PATCHED_SRC_DIR="$PRESENT_WORKING_DIR/code-editor-src"
CONFIG_FILE="$PRESENT_WORKING_DIR/configuration/$TARGET.json"

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file not found: $CONFIG_FILE" >&2
    exit 1
fi

echo "Using configuration: $CONFIG_FILE"
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

check_unsaved_changes() {
    local patches_path=$(jq -r '.patches.path' "$CONFIG_FILE")
    
    if [[ "$patches_path" == "null" || -z "$patches_path" ]]; then
        return
    fi
    
    if [[ ! -d "${PATCHED_SRC_DIR}" ]]; then
        return
    fi
    
    export QUILT_PATCHES="${PRESENT_WORKING_DIR}/patches"
    export QUILT_SERIES="${PRESENT_WORKING_DIR}/$patches_path"
    
    pushd "${PATCHED_SRC_DIR}"
    
    # Check if there are applied patches
    local applied_output
    applied_output=$(quilt applied 2>/dev/null || true)

    if [[ -z "$applied_output" ]]; then
        popd
        return
    fi
    
    # Check for unsaved changes with diff
    local diff_output
    diff_output=$(quilt diff -z 2>/dev/null || true)

    if [[ -n "$diff_output" ]]; then
        popd
        echo "Error: You have unsaved changes in the current patch."
        echo "Run 'quilt refresh' to update the patch with your changes."
        echo "Please refresh or revert your changes before rebasing again"
        exit 1
    fi
    
    popd
}

apply_changes() {
    echo "Creating patched source in directory: ${PATCHED_SRC_DIR}"

    # Read configuration from JSON file
    local patches_path=$(jq -r '.patches.path' "$CONFIG_FILE")
    local overrides_path=$(jq -r '.overrides.path' "$CONFIG_FILE")
    local package_lock_path=$(jq -r '."package-lock-overrides".path' "$CONFIG_FILE")
    
    patch_dir="${PRESENT_WORKING_DIR}/patches"
    echo "Set patch directory as: $patch_dir"

    export QUILT_PATCHES="${patch_dir}"
    export QUILT_SERIES="${PRESENT_WORKING_DIR}/$patches_path"
    echo "Using series file: $QUILT_SERIES"

    # Check for unsaved changes if in rebase mode
    if [[ "$REBASE" == "true" ]]; then
        check_unsaved_changes
    fi

    # Clean out the build directory
    echo "Cleaning build src dir"
    rm -rf "${PATCHED_SRC_DIR}"

    # Copy third party source
    echo "Copying third party source to the patch directory"
    rsync -a "${PRESENT_WORKING_DIR}/third-party-src/" "${PATCHED_SRC_DIR}"
    
    # Handle rebase if requested
    if [[ "$REBASE" == "true" ]]; then
        rebase
    else
        echo "Applying patches"
        pushd "${PATCHED_SRC_DIR}"
        quilt push -a
        popd
    fi

    echo "Applying overrides"
    rsync -a "${PRESENT_WORKING_DIR}/$overrides_path/" "${PATCHED_SRC_DIR}"

    echo "Applying package-lock overrides"
    rsync -a "${PRESENT_WORKING_DIR}/$package_lock_path/" "${PATCHED_SRC_DIR}"
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

rebase() {
    echo "Rebasing patches one by one..."
    pushd "${PATCHED_SRC_DIR}"
    
    # Apply patches one by one with force and merge
    while quilt push -f -m; do
        echo "Successfully applied patch: $(quilt top)"
    done
    
    # Check if we failed on a patch
    if quilt next >/dev/null 2>&1; then
        echo "Failed to apply patch: $(quilt next)"
        echo "Rebase stopped. Manual intervention required."
        exit 1
    else
        echo "All patches applied successfully"
    fi
    
    popd
}

echo "Preparing source for target: $TARGET"
if [[ "$REBASE" == "true" ]]; then
    echo "Rebase mode enabled"
fi
apply_changes
update_inline_sha
echo "Successfully prepared source for target: $TARGET"