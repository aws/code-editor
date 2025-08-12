#!/usr/bin/env bash

set -euo pipefail

determine_build_target() {
    local target="$1"
    local arch=$(uname -m)

    arch=${arch/x86_64/x64}
    
    case "$target" in
        "code-editor-server"|"code-editor-sagemaker-server")
            echo "vscode-reh-web-linux-${arch}"
            ;;
        "code-editor-web-embedded")
            echo "vscode-web"
            ;;
        *)
            echo "Error: Unknown target: $target" >&2
            exit 1
            ;;
    esac
}

determine_build_target "$1"