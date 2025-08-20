#!/bin/bash

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_SRC_DIR="$ROOT_DIR/code-editor-src"
THIRD_PARTY_SRC_DIR="$ROOT_DIR/third-party-src"
BUILD_DIR="$ROOT_DIR/build"

generate_oss_attribution() {
    local oss_attribution_dir="$BUILD_DIR/private/oss-attribution"
    local combined_oss_attribution_output_dir="${1:-$ROOT_DIR/overrides}"
    local code_oss_version=$(jq -r ".version" "$THIRD_PARTY_SRC_DIR/package.json")
    local code_oss_license=$(cat "$THIRD_PARTY_SRC_DIR/LICENSE.txt")
    local code_oss_third_party_licenses=$(cat "$THIRD_PARTY_SRC_DIR/ThirdPartyNotices.txt")
    additional_third_party_licenses=$(cat "$ROOT_DIR/build-tools/oss-attribution/additional-third-party-licenses.txt")

    npx --yes --package oss-attribution-generator@1.7.1 -- generate-attribution --baseDir "$BUILD_SRC_DIR" --outputDir "$oss_attribution_dir"
    attribution_licenses=$(cat "$oss_attribution_dir/attribution.txt")

    read_status=0
    read -r -d '' license_content << EOF || read_status=$?
$code_oss_third_party_licenses

---------------------------------------------------------

code-oss-dev $code_oss_version
https://github.com/microsoft/vscode

$code_oss_license

---------------------------------------------------------

$additional_third_party_licenses

---------------------------------------------------------
$attribution_licenses
EOF
    if [[ $read_status -eq 1 ]]; then
        echo "$license_content" > "$combined_oss_attribution_output_dir/LICENSE-THIRD-PARTY"
    else
        echo "Failed to generate OSS attribution"
        exit 1
    fi
}

generate_unified_oss_attribution() {
    local combined_oss_attribution_output_dir="${1:-$ROOT_DIR/overrides}"
    local targets=("code-editor-server" "code-editor-sagemaker-server" "code-editor-web-embedded" "code-editor-web-embedded-with-terminal")
    local target_dirs=()
    
    # Prepare source for each target in separate directories
    for target in "${targets[@]}"; do
        echo "Preparing source for $target"
        
        # Prepare source for this target
        "$ROOT_DIR/scripts/prepare-src.sh" "$target"
        
        # Move to target-specific directory
        mv "$ROOT_DIR/code-editor-src" "$ROOT_DIR/code-editor-src-$target"
        cd "$ROOT_DIR/code-editor-src-$target"
        npm install
        cd "$ROOT_DIR"
        
        # Check for unapproved licenses
        echo "Checking for unapproved licenses in $target..."
        local excluded_packages=""
        if [[ -f "$ROOT_DIR/build-tools/oss-attribution/excluded-packages.txt" ]]; then
            excluded_packages=$(tr '\n' ';' < "$ROOT_DIR/build-tools/oss-attribution/excluded-packages.txt" | sed 's/;$//')
        fi
        
        local output
        if [[ -n "$excluded_packages" ]]; then
            output=$(cd "$ROOT_DIR/code-editor-src-$target" && license-checker --production --exclude MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,0BSD --excludePackages '$excluded_packages' 2>/dev/null || true)
        else
            output=$(cd "$ROOT_DIR/code-editor-src-$target" && license-checker --production --exclude MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,0BSD 2>/dev/null || true)
        fi
        
        if [ -n "$output" ]; then
            echo "Unapproved licenses found in $target:"
            echo "$output"
            echo "Manual review required for unapproved licenses"
            exit 1
        fi
        
        target_dirs+=("$ROOT_DIR/code-editor-src-$target")
    done
    
    # Generate unified OSS attribution using multiple base directories
    echo "Generating unified OSS attribution for all targets"
    mkdir -p "$BUILD_DIR/private/oss-attribution"
    
    npx --yes --package oss-attribution-generator@1.7.1 -- generate-attribution \
        -b "${target_dirs[0]}" "${target_dirs[1]}" "${target_dirs[2]}" "${target_dirs[3]}" \
        --outputDir "$BUILD_DIR/private/oss-attribution"
    
    # Create final LICENSE-THIRD-PARTY with unified attribution
    local code_oss_version=$(jq -r ".version" "$THIRD_PARTY_SRC_DIR/package.json")
    local code_oss_license=$(cat "$THIRD_PARTY_SRC_DIR/LICENSE.txt")
    local code_oss_third_party_licenses=$(cat "$THIRD_PARTY_SRC_DIR/ThirdPartyNotices.txt")
    local additional_third_party_licenses=$(cat "$ROOT_DIR/build-tools/oss-attribution/additional-third-party-licenses.txt")
    local attribution_licenses=$(cat "$BUILD_DIR/private/oss-attribution/attribution.txt")
    
    cat > "$combined_oss_attribution_output_dir/LICENSE-THIRD-PARTY" << EOF
$code_oss_third_party_licenses

---------------------------------------------------------

code-oss-dev $code_oss_version
https://github.com/microsoft/vscode

$code_oss_license

---------------------------------------------------------

$additional_third_party_licenses

---------------------------------------------------------
$attribution_licenses
EOF
    
    # Clean up target directories
    rm -rf "$ROOT_DIR/code-editor-src-"*
}

# Parse command line arguments
COMMAND="generate_oss_attribution"
OUTPUT_DIR="$ROOT_DIR/overrides"

case "${1:-}" in
    --command)
        [[ $# -ge 2 ]] || { echo "--command requires a value" >&2; exit 1; }
        COMMAND="$2"
        OUTPUT_DIR="${3:-$OUTPUT_DIR}"
        ;;
    --*)
        echo "Unknown option $1" >&2
        exit 1
        ;;
    "")
        # No arguments, use defaults
        ;;
    *)
        OUTPUT_DIR="$1"
        ;;
esac

case "$COMMAND" in
    generate_oss_attribution)
        generate_oss_attribution "$OUTPUT_DIR"
        ;;
    generate_unified_oss_attribution)
        generate_unified_oss_attribution "$OUTPUT_DIR"
        ;;
    *)
        echo "Unknown command: $COMMAND" >&2
        echo "Available commands: generate_oss_attribution, generate_unified_oss_attribution" >&2
        exit 1
        ;;
esac