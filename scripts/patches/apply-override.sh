#!/usr/bin/env bash
#
# apply-override.sh — Generate or regenerate a quilt patch that overrides
# npm package versions in package.json files.
#
# Usage:
#   scripts/patches/apply-override.sh \
#     --patch common/override-example.diff \
#     --header 'Override example-pkg to ^2.0.0' \
#     --override 'global:example-pkg=^2.0.0' \
#     --override 'remote/package.json@global:example-pkg=^2.0.0'
#
# Override spec format: [FILE@]STRATEGY:PACKAGE=VERSION
#   FILE       — target package.json (default: package.json)
#   STRATEGY   — global | direct | direct-dev | nested
#   PACKAGE    — npm package name
#   VERSION    — semver spec (e.g. ^2.3.2)
#
# For nested: nested:PARENT:PACKAGE=VERSION
#
# This script is called by prepare-src.sh during rebase to regenerate
# @generated patches that fail to apply after an upstream Code-OSS bump.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PATCHED_SRC="${ROOT_DIR}/code-editor-src"
PATCHES_DIR="${ROOT_DIR}/patches"

# ---------------------------------------------------------------------------
# Parse CLI args
# ---------------------------------------------------------------------------
PATCH_NAME=""
HEADER=""
OVERRIDES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --patch)    PATCH_NAME="$2"; shift 2 ;;
        --header)   HEADER="$2"; shift 2 ;;
        --override) OVERRIDES+=("$2"); shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$PATCH_NAME" ]]; then echo "Error: --patch is required" >&2; exit 1; fi
if [[ -z "$HEADER" ]]; then echo "Error: --header is required" >&2; exit 1; fi
if [[ ${#OVERRIDES[@]} -eq 0 ]]; then echo "Error: at least one --override is required" >&2; exit 1; fi

PATCH_ENTRY="${PATCH_NAME%.diff}.diff"
PATCH_FILE="${PATCHES_DIR}/${PATCH_ENTRY}"

# ---------------------------------------------------------------------------
# Parse an override spec into: FILE, STRATEGY, PARENT, PACKAGE, VERSION
# ---------------------------------------------------------------------------
parse_spec() {
    local spec="$1"
    SPEC_FILE="package.json"
    local rest="$spec"

    # Check for FILE@ prefix
    if [[ "$spec" == *"@"* ]]; then
        local before_at="${spec%%@*}"
        if [[ "$before_at" != *":"* ]]; then
            SPEC_FILE="$before_at"
            rest="${spec#*@}"
        fi
    fi

    local strategy="${rest%%:*}"
    local pkg_ver="${rest#*:}"
    SPEC_STRATEGY="$strategy"
    SPEC_PARENT=""

    if [[ "$strategy" == "nested" ]]; then
        # nested:PARENT:PACKAGE=VERSION
        local after_nested="${rest#nested:}"
        SPEC_PARENT="${after_nested%%:*}"
        pkg_ver="${after_nested#*:}"
    fi

    SPEC_PACKAGE="${pkg_ver%%=*}"
    SPEC_VERSION="${pkg_ver#*=}"
}

# ---------------------------------------------------------------------------
# Apply a single override to a package.json using jq
# ---------------------------------------------------------------------------
apply_override() {
    local file="$1"
    local strategy="$2"
    local parent="$3"
    local package="$4"
    local version="$5"
    local abs_path="${PATCHED_SRC}/${file}"

    if [[ ! -f "$abs_path" ]]; then
        echo "Error: ${file} not found in code-editor-src/" >&2
        exit 1
    fi

    case "$strategy" in
        global)
            jq --arg pkg "$package" --arg ver "$version" \
                '.overrides[$pkg] = $ver' "$abs_path" > "${abs_path}.tmp"
            ;;
        direct)
            jq --arg pkg "$package" --arg ver "$version" \
                '.dependencies[$pkg] = $ver' "$abs_path" > "${abs_path}.tmp"
            ;;
        direct-dev)
            jq --arg pkg "$package" --arg ver "$version" \
                '.devDependencies[$pkg] = $ver' "$abs_path" > "${abs_path}.tmp"
            ;;
        nested)
            jq --arg parent "$parent" --arg pkg "$package" --arg ver "$version" \
                '.overrides[$parent][$pkg] = $ver' "$abs_path" > "${abs_path}.tmp"
            ;;
        *)
            echo "Unknown strategy: $strategy" >&2; exit 1
            ;;
    esac

    mv "${abs_path}.tmp" "$abs_path"
    echo "  Applied: ${file} ${strategy}:${package}=${version}"
}

# ---------------------------------------------------------------------------
# Build metadata header
# ---------------------------------------------------------------------------
build_metadata() {
    local cli_args="--patch ${PATCH_ENTRY}"
    for o in "${OVERRIDES[@]}"; do
        cli_args+=" --override '${o}'"
    done

    echo "$HEADER"
    echo ""
    echo "@generated"
    echo "@generator: scripts/patches/apply-override.sh ${cli_args}"

    # Collect unique @override-package entries
    local -A seen_pkg=()
    for o in "${OVERRIDES[@]}"; do
        parse_spec "$o"
        [[ "$SPEC_STRATEGY" == "direct-dev" ]] && continue

        local pkg_key="${SPEC_PACKAGE}@${SPEC_VERSION}"
        if [[ -z "${seen_pkg[$pkg_key]:-}" ]]; then
            seen_pkg[$pkg_key]=1
            echo "@override-package: ${pkg_key}"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if [[ ! -d "$PATCHED_SRC" ]]; then
    echo "Error: code-editor-src/ does not exist. Run prepare-src.sh first." >&2
    exit 1
fi

# Find the first series file for quilt env
SERIES_FILE=$(find "$PATCHES_DIR" -maxdepth 1 -name "*.series" | head -1)
if [[ -z "$SERIES_FILE" ]]; then
    echo "Error: No series files found in patches/" >&2
    exit 1
fi

export QUILT_PATCHES="$PATCHES_DIR"
export QUILT_SERIES="$SERIES_FILE"

PATCH_EXISTS=false
[[ -f "$PATCH_FILE" ]] && PATCH_EXISTS=true

pushd "$PATCHED_SRC" > /dev/null

# Create or reset the patch
if [[ "$PATCH_EXISTS" == false ]]; then
    quilt pop -qa 2>/dev/null || true
    quilt new "$PATCH_ENTRY"
else
    # Pop to this patch, then refresh will regenerate it
    quilt pop -q "$PATCH_ENTRY" 2>/dev/null || true
    quilt push -q "$PATCH_ENTRY" 2>/dev/null || true
fi

# Track and apply each override
for o in "${OVERRIDES[@]}"; do
    parse_spec "$o"
    quilt add "$SPEC_FILE" 2>/dev/null || true
    apply_override "$SPEC_FILE" "$SPEC_STRATEGY" "$SPEC_PARENT" "$SPEC_PACKAGE" "$SPEC_VERSION"
done

quilt refresh -p ab --no-timestamps

popd > /dev/null

# Write metadata header (strip any existing header to avoid duplicates)
METADATA=$(build_metadata)
# Strip existing header: everything before the first "Index:" or "---" diff marker
PATCH_CONTENT=$(sed -n '/^Index:\|^--- /,$p' "$PATCH_FILE")
printf '%s\n\n%s\n' "$METADATA" "$PATCH_CONTENT" > "$PATCH_FILE"

# Push remaining patches
pushd "$PATCHED_SRC" > /dev/null
quilt push -a 2>/dev/null || true
popd > /dev/null

# Add to all series files if new
if [[ "$PATCH_EXISTS" == false ]]; then
    for sf in "$PATCHES_DIR"/*.series; do
        if ! grep -q "^${PATCH_ENTRY}$" "$sf"; then
            # Insert after last common/ entry
            local_last=$(grep -n "^common/" "$sf" | tail -1 | cut -d: -f1)
            if [[ -n "$local_last" ]]; then
                sed -i "${local_last}a\\${PATCH_ENTRY}" "$sf"
            else
                echo "$PATCH_ENTRY" >> "$sf"
            fi
        fi
    done
fi

echo ""
echo "Patch created: ${PATCH_ENTRY}"
