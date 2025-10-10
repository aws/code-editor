#!/bin/bash

set -e

TARGETS=(code-editor-server code-editor-sagemaker-server code-editor-web-embedded code-editor-web-embedded-with-terminal)

echo "Updating package-lock overrides for all targets..."

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

# Generate unified OSS attribution
echo ""
echo "Generating unified OSS attribution..."
./scripts/generate-oss-attribution.sh --command generate_unified_oss_attribution

# Copy LICENSE-THIRD-PARTY to root directory
cp overrides/LICENSE-THIRD-PARTY LICENSE-THIRD-PARTY

# Clean up prepared source directories
echo "Cleaning up prepared source directories..."
for target in "${TARGETS[@]}"; do
  rm -rf "code-editor-src-$target"
done

echo ""
echo "Package-lock overrides and OSS attribution updated successfully!"
echo "Review the changes and commit them when ready."