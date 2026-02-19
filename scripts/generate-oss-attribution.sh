#!/bin/bash

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_SRC_DIR="$ROOT_DIR/code-editor-src"
THIRD_PARTY_SRC_DIR="$ROOT_DIR/third-party-src"
BUILD_DIR="$ROOT_DIR/build"
OSS_ATTRIBUTION_DIR="$ROOT_DIR/build-tools/oss-attribution"
OSS_ATTRIBUTION_PKG_DIR="$OSS_ATTRIBUTION_DIR/oss-attribution-generator"

check_excluded_package_licenses() {
    local target="$1"
    local src_dir="$2"
    
    echo "Checking excluded packages for license changes in $target..."
    
    # Check if excluded packages file exists
    if [[ ! -f "$OSS_ATTRIBUTION_DIR/excluded-packages.json" ]]; then
        echo "No excluded packages JSON file found, skipping license change check"
        return 0
    fi
    
    # Read excluded packages with their approved licenses from JSON
    local packages
    packages=$(jq -r 'keys[]' "$OSS_ATTRIBUTION_DIR/excluded-packages.json")
    
    while IFS= read -r package_name; do
        local approved_license
        approved_license=$(jq -r ".\"$package_name\"" "$OSS_ATTRIBUTION_DIR/excluded-packages.json")
        
        echo "Checking $package_name for license changes (approved: $approved_license)..."
        
        # Check if this specific package has a different license than approved
        local output
        output=$(cd "$src_dir" && license-checker --production --packages "$package_name" --exclude "$approved_license" 2>/dev/null || true)
        
        if [ -n "$output" ]; then
            echo "License change detected for excluded package $package_name:"
            echo "$output"
            echo "Expected: $approved_license"
            echo "Manual review required for license change"
            exit 1
        fi
    done <<< "$packages"
}

check_unapproved_licenses() {
    local target="$1"
    local src_dir="$2"
    
    echo "Checking for unapproved licenses in $target..."
    
    # Build excluded packages list from JSON file
    local excluded_packages=""
    if [[ -f "$OSS_ATTRIBUTION_DIR/excluded-packages.json" ]]; then
        excluded_packages=$(jq -r 'keys | join(";")' "$OSS_ATTRIBUTION_DIR/excluded-packages.json")
    fi
    
    local output
    if [[ -n "$excluded_packages" ]]; then
        output=$(cd "$src_dir" && eval "license-checker --production --exclude MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,0BSD --excludePackages '$excluded_packages'" 2>/dev/null || true)   
    else
        output=$(cd "$src_dir" && license-checker --production --exclude MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,0BSD 2>/dev/null || true)
    fi
    
    if [ -n "$output" ]; then
        echo "Unapproved licenses found in $target:"
        echo "$output"
        echo "Manual review required for unapproved licenses"
        exit 1
    fi
    
    # Also check excluded packages for license changes
    check_excluded_package_licenses "$target" "$src_dir"
}

generate_oss_attribution() {
    local combined_oss_attribution_output_dir="${1:-$ROOT_DIR/overrides}"
    local target="$2"
    local oss_attribution_dir="$BUILD_DIR/private/oss-attribution"
    local code_oss_version=$(jq -r ".version" "$THIRD_PARTY_SRC_DIR/package.json")
    local code_oss_license=$(cat "$THIRD_PARTY_SRC_DIR/LICENSE.txt")
    local code_oss_third_party_licenses=$(cat "$THIRD_PARTY_SRC_DIR/ThirdPartyNotices.txt")
    additional_third_party_licenses=$(cat "$OSS_ATTRIBUTION_DIR/additional-third-party-licenses.txt")

    # Prepare source for target if specified
    if [ -n "$target" ]; then
        "$ROOT_DIR/scripts/prepare-src.sh" "$target"
        cd "$BUILD_SRC_DIR"
        npm ci
        cd "$ROOT_DIR"
        
        check_unapproved_licenses "$target" "$BUILD_SRC_DIR"
    fi

    npm ci --prefix "$OSS_ATTRIBUTION_PKG_DIR"
    npx --prefix "$OSS_ATTRIBUTION_PKG_DIR" generate-attribution --baseDir "$BUILD_SRC_DIR" --outputDir "$oss_attribution_dir"
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
    
    if [[ "$PREPARE_SOURCES" == "true" ]]; then
        echo "Preparing sources from scratch"
        for target in "${targets[@]}"; do
            echo "Preparing source for $target"
            
            "$ROOT_DIR/scripts/prepare-src.sh" "$target"
            mv "$ROOT_DIR/code-editor-src" "$ROOT_DIR/code-editor-src-$target"
            cd "$ROOT_DIR/code-editor-src-$target"
            npm ci
            cd "$ROOT_DIR"
            
            target_dirs+=("$ROOT_DIR/code-editor-src-$target")
        done
    else
        # Check that all target directories exist
        local missing_targets=()
        for target in "${targets[@]}"; do
            if [[ -d "$ROOT_DIR/code-editor-src-$target" ]]; then
                echo "Found existing prepared source for $target"
                target_dirs+=("$ROOT_DIR/code-editor-src-$target")
            else
                missing_targets+=("$target")
            fi
        done
        
        if [[ ${#missing_targets[@]} -gt 0 ]]; then
            echo "Error: Missing prepared source directories for targets: ${missing_targets[*]}" >&2
            echo "Use --prepare-sources flag to prepare sources automatically" >&2
            exit 1
        fi
    fi
    
    # Check licenses for all targets
    for target in "${targets[@]}"; do
        check_unapproved_licenses "$target" "$ROOT_DIR/code-editor-src-$target"
    done
    
    # Generate unified OSS attribution using multiple base directories
    echo "Generating unified OSS attribution for all targets"
    mkdir -p "$BUILD_DIR/private/oss-attribution"
    
    npm ci --prefix "$OSS_ATTRIBUTION_PKG_DIR"
    npx --prefix "$OSS_ATTRIBUTION_PKG_DIR" generate-attribution \
        -b "${target_dirs[0]}" "${target_dirs[1]}" "${target_dirs[2]}" "${target_dirs[3]}" \
        --outputDir "$BUILD_DIR/private/oss-attribution"
    
    # Create final LICENSE-THIRD-PARTY with unified attribution
    local code_oss_version=$(jq -r ".version" "$THIRD_PARTY_SRC_DIR/package.json")
    local code_oss_license=$(cat "$THIRD_PARTY_SRC_DIR/LICENSE.txt")
    local code_oss_third_party_licenses=$(cat "$THIRD_PARTY_SRC_DIR/ThirdPartyNotices.txt")
    local additional_third_party_licenses=$(cat "$OSS_ATTRIBUTION_DIR/additional-third-party-licenses.txt")
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
    
    # Only clean up if we prepared the sources in this run
    if [[ "$PREPARE_SOURCES" == "true" ]]; then
        rm -rf "$ROOT_DIR/code-editor-src-"*
    fi
}

# Parse command line arguments
COMMAND="generate_oss_attribution"
OUTPUT_DIR="$ROOT_DIR/overrides"
PREPARE_SOURCES=false
TARGET="code-editor-server"

while [[ $# -gt 0 ]]; do
    case $1 in
        --command)
            COMMAND="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --prepare-sources)
            PREPARE_SOURCES=true
            shift
            ;;
        --*)
            echo "Unknown option $1" >&2
            exit 1
            ;;
        *)
            echo "Error: Unexpected argument '$1'" >&2
            exit 1
            ;;
    esac
done

case "$COMMAND" in
    generate_oss_attribution)
        generate_oss_attribution "$OUTPUT_DIR" "$TARGET"
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