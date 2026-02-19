#!/usr/bin/env bash

set -e

# Function to scan main application dependencies
scan_main_dependencies() {
    local target="$1"
    local head_ref="$2"
    
    echo "Security Scanning Started"
    echo "Target: $target"
    echo "PR Branch (code being scanned): $head_ref"

    # Define directories to scan with their specific configurations
    local scan_configs=(
        "code-editor-src::root"
        "remote::subdir_ignore_errors"
        "extensions::subdir_ignore_errors"
        "remote/web::subdir_ignore_errors"
    )
    local scan_results=()
    
    # Scan each directory
    for config in "${scan_configs[@]}"; do
        local dir=$(echo "$config" | cut -d':' -f1)
        local scan_type=$(echo "$config" | cut -d':' -f3)
        
        echo "=== Scanning directory: $dir ==="
        
        # For the first scan (code-editor-src), we need to check the root directory
        # For others, we need to check subdirectories within code-editor-src
        local check_dir
        if [ "$scan_type" = "root" ]; then
            check_dir="$dir"
        else
            check_dir="code-editor-src/$dir"
        fi
        
        # Check if directory exists and has package-lock.json
        if [ ! -d "$check_dir" ]; then
            echo "Error: Directory $check_dir does not exist."
            exit 1
        fi
        
        if [ ! -f "$check_dir/package-lock.json" ]; then
            echo "Error: No package-lock.json found in $check_dir."
            exit 1
        fi
        
        # Generate SBOM for this directory
        echo "Generating SBOM for $dir"
        
        # Create a safe filename for the SBOM
        local safe_dir_name=$(echo "$dir" | sed 's/\//_/g')
        local sbom_file="${safe_dir_name}-sbom.json"
        local result_file="${safe_dir_name}-scan-result.json"
        
        # Handle different scan types
        if [ "$scan_type" = "root" ]; then
            # First scan: cd into code-editor-src and run scan there
            echo "Scanning root directory: $dir"
            cd "$dir"
            cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o "$sbom_file"
            
        elif [ "$scan_type" = "subdir_ignore_errors" ]; then
            # Subdirectory scans with npm error handling: cd into directory and add --ignore-npm-errors flag
            # This is to ignore extraneous npm errors that don't affect the security scan
            # This behaviour is same for internal scanning.
            echo "Scanning subdirectory: $dir (ignoring npm errors)"
            cd "$check_dir"
            cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 --ignore-npm-errors -o "$sbom_file"
        fi
        
        echo "Invoking Inspector's ScanSbom API for $dir"
        aws inspector-scan scan-sbom --sbom "file://$sbom_file" > "$result_file"
        
        # Store the result file path for later analysis
        scan_results+=("$PWD/$result_file")
        
        # Return to root directory for next iteration
        cd - > /dev/null
        
        echo "Completed scan for $dir"
    done
    
    # Store scan results paths in a file for the analyze step
    printf '%s\n' "${scan_results[@]}" > scan_results_paths.txt
}

# Function to generate SBOMs for additional dependencies
generate_additional_sboms() {
    echo "Generating SBOMs for additional dependencies"
    
    # Store current working directory
    local root_dir=$(pwd)
    
    # Create directory for additional SBOMs
    mkdir -p additional-node-js-sboms
    
    # 1. Generate SBOM for oss-attribution-generator
    echo "Generating SBOM for oss-attribution-generator"
    
    oss_attribution_dir="$root_dir/build-tools/oss-attribution/oss-attribution-generator"
    
    echo "Found OSS attribution generator at: $oss_attribution_dir"
    cd "$oss_attribution_dir"
    cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o "$root_dir/additional-node-js-sboms/oss-attribution-generator-sbom.json"
    cd - > /dev/null
    echo "Generated SBOM for OSS attribution generator"
    
    # 2. Generate SBOM for semver package
    echo "Generating SBOM for semver package"
    
    # Find the global npm modules directory
    global_npm_dir=$(npm list -g | head -1)
    semver_dir="$global_npm_dir/node_modules/semver"
    
    echo "Found semver package at: $semver_dir"
    cd "$semver_dir"
    npm install --omit dev
    cyclonedx-npm --omit dev --output-reproducible --spec-version 1.5 -o "$root_dir/additional-node-js-sboms/semver-sbom.json"
    cd - > /dev/null
    echo "Generated SBOM for semver package"
    
    # 3. Generate SBOM for Node.js linux-x64 binary
    echo "Generating SBOM for Node.js linux-x64 binary"
    
    # Read Node.js version from .npmrc file
    NODE_VERSION=$(grep 'target=' third-party-src/remote/.npmrc | cut -d'"' -f2)
    
    node_x64_dir="nodejs-binaries/node-v$NODE_VERSION-linux-x64"
    echo "Found Node.js x64 binary at: $node_x64_dir"
    syft "$node_x64_dir" -o cyclonedx-json@1.5="$root_dir/additional-node-js-sboms/nodejs-x64-sbom.json"
    echo "Generated SBOM for Node.js x64 binary"
    
    # 4. Generate SBOM for Node.js linux-arm64 binary
    echo "Generating SBOM for Node.js linux-arm64 binary"
    
    node_arm64_dir="nodejs-binaries/node-v$NODE_VERSION-linux-arm64"
    echo "Found Node.js ARM64 binary at: $node_arm64_dir"
    syft "$node_arm64_dir" -o cyclonedx-json@1.5="$root_dir/additional-node-js-sboms/nodejs-arm64-sbom.json"
    echo "Generated SBOM for Node.js ARM64 binary"
    
    # List generated SBOMs
    echo "Generated additional SBOMs:"
    ls -la additional-node-js-sboms/
    
    echo "Additional SBOM generation completed successfully"
}

# Function to scan additional SBOMs using AWS Inspector
scan_additional_sboms() {
    echo "Scanning additional SBOMs with AWS Inspector"
      
    echo "Downloading Node.js binaries..."
    download_nodejs_binaries
    
    echo "Generating additional SBOMs..."
    generate_additional_sboms
    
    # Create directory for additional scan results
    mkdir -p additional-scan-results
    
    # Check if additional SBOMs directory exists (should exist after generation)
    if [ ! -d "additional-node-js-sboms" ]; then
        echo "Error: additional-node-js-sboms directory not found after generation"
        exit 1
    fi
    
    # Array to store scan result files for later analysis
    local additional_scan_results=()
    
    # Scan each SBOM file in the additional-node-js-sboms directory
    for sbom_file in additional-node-js-sboms/*.json; do
        if [ ! -f "$sbom_file" ]; then
            echo "Warning: No SBOM files found in additional-node-js-sboms directory"
            continue
        fi
        
        # Extract base filename without path and extension
        local base_name=$(basename "$sbom_file" .json)
        local result_file="additional-scan-results/${base_name}-scan-result.json"
        
        echo "Scanning SBOM: $sbom_file"
        echo "Output will be saved to: $result_file"
        
        # Run AWS Inspector scan on the SBOM
        aws inspector-scan scan-sbom --sbom "file://$sbom_file" > "$result_file"
        
        # Store the result file path for later analysis
        additional_scan_results+=("$PWD/$result_file")
        
        echo "Completed scan for $base_name"
    done
    
    # Store additional scan results paths in a file for the analyze step
    printf '%s\n' "${additional_scan_results[@]}" > additional_scan_results_paths.txt
    
    echo "Additional SBOM scanning completed successfully"
    echo "Scan results saved in additional-scan-results/ directory"
    ls -la additional-scan-results/
}

# Function to download Node.js binaries for scanning
download_nodejs_binaries() {
    echo "Downloading Node.js prebuilt binaries for scanning"
    
    # Create directory for Node.js binaries
    mkdir -p nodejs-binaries
    cd nodejs-binaries
    
    # Read Node.js version from .npmrc file
    if [ -f "../third-party-src/remote/.npmrc" ]; then
        NODE_VERSION=$(grep 'target=' ../third-party-src/remote/.npmrc | cut -d'"' -f2)
        echo "Found Node.js version $NODE_VERSION in .npmrc"
    else
        echo "ERROR: Unable to determine NODE_VERSION"
        exit 1
    fi
    
    echo "Downloading Node.js v$NODE_VERSION for linux-x64"
    curl -sSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" -o "node-v$NODE_VERSION-linux-x64.tar.xz"
    
    echo "Downloading Node.js v$NODE_VERSION for linux-arm64"
    curl -sSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-arm64.tar.xz" -o "node-v$NODE_VERSION-linux-arm64.tar.xz"
    
    echo "Extracting Node.js binaries"
    tar -xf "node-v$NODE_VERSION-linux-x64.tar.xz"
    tar -xf "node-v$NODE_VERSION-linux-arm64.tar.xz"
    
    echo "Node.js binaries downloaded and extracted:"
    ls -la
    
    # Return to root directory
    cd - > /dev/null
    
    echo "Node.js dependencies preparation completed"
}

# Function to analyze SBOM scan results
analyze_sbom_results() {
    local target="$1"
    local results_file="$2"
    
    if [ -z "$results_file" ]; then
        echo "Error: Results file path is required as second parameter"
        exit 1
    fi

    if [ ! -f "$results_file" ]; then
        echo "Error: Scan results paths file '$results_file' not found"
        exit 1
    fi
    
    # Initialize totals
    local total_critical=0
    local total_high=0
    local total_medium=0
    local total_other=0
    local total_low=0
    
    echo "=== SBOM Security Scan Results for $target ==="
    
    # Process each scan result file
    while IFS= read -r result_file; do
        if [ ! -f "$result_file" ]; then
            echo "Warning: Scan result file $result_file not found, skipping..."
            continue
        fi
        
        # Extract directory name from result file path
        local dir_name=$(basename "$result_file" | sed 's/-scan-result\.json$//' | sed 's/_/\//g')
        
        echo ""
        echo "--- Results for $dir_name ---"
        
        # Extract vulnerability counts from this scan result
        local critical=$(jq -r '.sbom.vulnerability_count.critical // 0' "$result_file")
        local high=$(jq -r '.sbom.vulnerability_count.high // 0' "$result_file")
        local medium=$(jq -r '.sbom.vulnerability_count.medium // 0' "$result_file")
        local other=$(jq -r '.sbom.vulnerability_count.other // 0' "$result_file")
        local low=$(jq -r '.sbom.vulnerability_count.low // 0' "$result_file")
        
        echo "Critical: $critical, High: $high, Medium: $medium, Other: $other, Low: $low"
        
        # Add to totals
        total_critical=$((total_critical + critical))
        total_high=$((total_high + high))
        total_medium=$((total_medium + medium))
        total_other=$((total_other + other))
        total_low=$((total_low + low))
        
        # Check for concerning vulnerabilities in this directory
        local dir_concerning=$((critical + high + medium + other))
        if [ $dir_concerning -gt 0 ]; then
            echo "⚠️  Found $dir_concerning concerning vulnerabilities in $dir_name"
        else
            echo "✅ No concerning vulnerabilities in $dir_name"
        fi
        
    done < "$results_file"
    
    echo ""
    echo "=== TOTAL SCAN RESULTS ==="
    echo "Total Critical vulnerabilities: $total_critical"
    echo "Total High vulnerabilities: $total_high"
    echo "Total Medium vulnerabilities: $total_medium"
    echo "Total Other vulnerabilities: $total_other"
    echo "Total Low vulnerabilities: $total_low"
    echo "=================================================="
    
    # Calculate total concerning vulnerabilities (excluding low)
    local total_concerning=$((total_critical + total_high + total_medium + total_other))
    
    if [ $total_concerning -gt 0 ]; then
        echo "❌ Security scan FAILED: Found $total_concerning concerning vulnerabilities across all directories"
        echo "Critical: $total_critical, High: $total_high, Medium: $total_medium, Other: $total_other"
        exit 1
    else
        echo "✅ Security scan PASSED: No concerning vulnerabilities found across all directories"
        echo "Total Low vulnerabilities: $total_low (acceptable)"
    fi
}

# Function to scan GitHub security advisories for microsoft/vscode
scan_github_advisories() {
    echo "Scanning GitHub security advisories for microsoft/vscode"
    
    local repo_owner="microsoft"
    local repo_name="vscode"
    local vscode_version=$(jq -r '.version' third-party-src/package.json)
    local backported_file="patches/backported-patches.json"
    
    echo "Found VS Code version: $vscode_version"
    
    # Load backported patches list if exists
    local -A backported_patches
    if [ -f "$backported_file" ]; then
        echo "Loading backported patches from $backported_file"
        local finding_ids=$(jq -r '.[].finding_id' "$backported_file")
        while IFS= read -r finding_id; do
            [ -n "$finding_id" ] && backported_patches["$finding_id"]=1
        done <<< "$finding_ids"
        echo "Loaded ${#backported_patches[@]} backported patches to ignore"
    fi
    
    echo "Fetching security advisories from GitHub API for $repo_owner/$repo_name"
    
    # Fetch security advisories using GitHub CLI
    local temp_file=$(mktemp)
    
    # Make API request using gh cli with proper headers
    if ! gh api \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        "/repos/$repo_owner/$repo_name/security-advisories" > "$temp_file"; then
        echo "Error: Failed to fetch GitHub security advisories using GitHub CLI"
        echo "Make sure GitHub CLI is installed and authenticated"
        rm -f "$temp_file"
        exit 1
    fi
    
    # Check if the response is valid JSON and not an error
    if ! jq empty "$temp_file" 2>/dev/null; then
        echo "Error: Invalid JSON response from GitHub API"
        cat "$temp_file"
        rm -f "$temp_file"
        exit 1
    fi
    
    # Count total advisories
    local total_advisories=$(jq length "$temp_file")
    echo "Found $total_advisories total advisories for $repo_owner/$repo_name"
    
    if [ "$total_advisories" -eq 0 ]; then
        echo "✅ No security advisories found for microsoft/vscode"
        rm -f "$temp_file"
        return 0
    fi
    
    # Process advisories
    local concerning_advisories=0
    
    echo ""
    echo "=== GITHUB SECURITY ADVISORIES ANALYSIS ==="
    
    # Process each advisory
    local advisory_index=0
    local total_advisories_count=$(jq length "$temp_file")
    
    while [ $advisory_index -lt $total_advisories_count ]; do
        local advisory=$(jq -c ".[$advisory_index]" "$temp_file")
        local ghsa_id=$(echo "$advisory" | jq -r '.ghsa_id // "N/A"')
        local cve_id=$(echo "$advisory" | jq -r '.cve_id // "N/A"')
        local severity=$(echo "$advisory" | jq -r '.severity // "unknown"')
        local summary=$(echo "$advisory" | jq -r '.summary // "No summary available"')
        local published_at=$(echo "$advisory" | jq -r '.published_at // "N/A"')
        
        echo ""
        echo "Advisory: $ghsa_id"
        [ "$cve_id" != "N/A" ] && echo "CVE: $cve_id"
        echo "Severity: $severity"
        echo "Published: $published_at"
        echo "Summary: $summary"
        
        local is_version_affected=false
        
        # Check if current version is affected using semver
        local vulnerable_ranges=$(echo "$advisory" | jq -r '.vulnerabilities[].vulnerable_version_range // empty')
        
        if [ -n "$vulnerable_ranges" ]; then
            # Process each vulnerable range
            local ranges_array=()
            
            # Convert vulnerable ranges to array
            while IFS= read -r range; do
                if [ -n "$range" ]; then
                    ranges_array+=("$range")
                fi
            done <<< "$vulnerable_ranges"
            
            # Check each range
            for vulnerable_range in "${ranges_array[@]}"; do
                echo "Vulnerable versions: $vulnerable_range"
                
                # Use semver range to check if current version is in the vulnerable range
                if semver --range "$vulnerable_range" "$vscode_version" >/dev/null 2>&1; then
                    echo "⚠️  Version $vscode_version is affected by this advisory (in range: $vulnerable_range)"
                    is_version_affected=true
                else
                    echo "✅ Version $vscode_version is not in vulnerable range: $vulnerable_range"
                fi
            done
            

        else
            echo "⚠️  No version range specified - assuming potentially affected"
            is_version_affected=true
        fi
        
        # Check if this advisory is in the backported patches list
        if [[ -v backported_patches["$ghsa_id"] ]] || [[ "$cve_id" != "N/A" && -v backported_patches["$cve_id"] ]]; then
            echo "ℹ️  Ignoring - patch backported to current version"
            advisory_index=$((advisory_index + 1))
            continue
        fi
        
        # Count concerning advisories based on combined criteria
        # Advisory is concerning if BOTH conditions are met:
        # 1. Version is affected AND 2. Severity is medium/high/critical
        if [ "$is_version_affected" = true ] && ([ "$severity" = "medium" ] || [ "$severity" = "high" ] || [ "$severity" = "critical" ]); then
            echo "Incrementing count"
            concerning_advisories=$((concerning_advisories + 1))
        fi
        
        advisory_index=$((advisory_index + 1))
    done
    
    echo ""
    echo "=== GITHUB ADVISORIES SUMMARY ==="
    echo "Total advisories found: $total_advisories"
    echo "Concerning advisories: $concerning_advisories"
    echo "=================================================="
    
    # Clean up temp files
    rm -f "$temp_file"
    
    # Determine if we should fail based on concerning advisories
    if [ "$concerning_advisories" -gt 0 ]; then
        echo "⚠️  Found $concerning_advisories concerning GitHub security advisories for microsoft/vscode"
        echo "Review the advisories above to determine if they affect your VS Code integration"
        exit 1
    else
        echo "✅ No concerning GitHub security advisories found for microsoft/vscode"
        return 0
    fi
}

# Main function to handle command line arguments
main() {
    case "$1" in
        "scan-main-dependencies")
            scan_main_dependencies "$2" "$3"
            ;;
        "analyze-results")
            analyze_sbom_results "$2" "$3"
            ;;
        "scan-additional-dependencies")
            scan_additional_sboms
            ;;
        "scan-github-advisories")
            scan_github_advisories
            ;;
        *)
            echo "Usage: $0 {scan-main-dependencies|analyze-results|scan-additional-dependencies|scan-github-advisories}"
            echo "  scan-main-dependencies: Generate SBOMs and scan main application dependencies"
            echo "  analyze-results: Analyze SBOM scan results and fail if vulnerabilities found"
            echo "  scan-additional-dependencies: Download, generate SBOMs, and scan additional Node.js dependencies"
            echo "  scan-github-advisories: Scan GitHub security advisories for microsoft/vscode"
            exit 1
            ;;
    esac
}

# Call main function with all arguments
main "$@"