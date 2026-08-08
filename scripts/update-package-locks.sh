#!/bin/bash

set -e

ALL_TARGETS=(code-editor-server code-editor-sagemaker-server code-editor-web-embedded code-editor-web-embedded-with-terminal)

# Parse command line arguments
SELECTED_TARGETS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      [[ $# -ge 2 ]] || { echo "Error: --target requires a value" >&2; exit 1; }
      if [[ ! -f "configuration/$2.json" ]]; then
        echo "Error: Unknown target: $2" >&2
        echo "Available targets: ${ALL_TARGETS[*]}" >&2
        exit 1
      fi
      SELECTED_TARGETS+=("$2")
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [--target <target>]..." >&2
      exit 1
      ;;
  esac
done

if [[ ${#SELECTED_TARGETS[@]} -gt 0 ]]; then
  TARGETS=("${SELECTED_TARGETS[@]}")
else
  TARGETS=("${ALL_TARGETS[@]}")
fi

# Unified OSS attribution needs all targets prepared
RUN_ATTRIBUTION=true
for target in "${ALL_TARGETS[@]}"; do
  found=false
  for selected in "${TARGETS[@]}"; do
    [[ "$selected" == "$target" ]] && found=true
  done
  if [[ "$found" == false ]]; then
    RUN_ATTRIBUTION=false
  fi
done

echo "Updating package-lock overrides for targets: ${TARGETS[*]}"

# Clean up any existing prepared source directories
for target in "${TARGETS[@]}"; do
  rm -rf "code-editor-src-$target"
done

# Process each target
for target in "${TARGETS[@]}"; do
  echo ""
  echo "=== PROCESSING TARGET: $target ==="
  
  # Prepare source
  echo "Preparing source for $target"
  ./scripts/prepare-src.sh "$target"
  
  # Install dependencies
  echo "Installing dependencies for $target"
  cd code-editor-src
  npm install
  cd ..
  
  # Rename to target-specific directory for OSS attribution
  mv code-editor-src "code-editor-src-$target"
  
  # Update package-lock overrides
  echo "Updating package-lock overrides for $target"
  OVERRIDE_PATH=$(jq -r '."package-lock-overrides".path' "configuration/$target.json")
  
  rm -rf "$OVERRIDE_PATH"
  mkdir -p "$OVERRIDE_PATH"
  
  while IFS= read -r -d '' file; do
    rel_path="${file#code-editor-src-$target/}"
    third_party_file="third-party-src/$rel_path"
    
    # Skip files in node_modules
    if [[ "$rel_path" == node_modules/* ]]; then
      continue
    fi
    
    if [ ! -f "$third_party_file" ] || ! cmp -s "$file" "$third_party_file"; then
      dest_dir="$OVERRIDE_PATH/$(dirname "$rel_path")"
      mkdir -p "$dest_dir"
      cp "$file" "$dest_dir/"
      echo "Copied updated $rel_path to $OVERRIDE_PATH"
    fi
  done < <(find "code-editor-src-$target" -name "package-lock.json" -type f -print0)
  
  echo "=== COMPLETED TARGET: $target ==="
done

# Generate unified OSS attribution (requires all targets prepared)
if [[ "$RUN_ATTRIBUTION" == true ]]; then
  echo ""
  echo "Generating unified OSS attribution..."
  ./scripts/generate-oss-attribution.sh --command generate_unified_oss_attribution

  # Copy LICENSE-THIRD-PARTY to root directory
  cp overrides/LICENSE-THIRD-PARTY LICENSE-THIRD-PARTY
else
  echo ""
  echo "Skipping unified OSS attribution: it requires all targets to be prepared."
  echo "Run this script without --target, or run ./scripts/generate-oss-attribution.sh --command generate_unified_oss_attribution separately."
fi

# Clean up prepared source directories
echo "Cleaning up prepared source directories..."
for target in "${TARGETS[@]}"; do
  rm -rf "code-editor-src-$target"
done

echo ""
echo "Package-lock overrides and OSS attribution updated successfully!"
echo "Review the changes and commit them when ready."