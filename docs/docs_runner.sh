#!/bin/bash
set -e

# 1. Navigate to where the data files are.
cd "$(dirname "$0")"

echo "Generating documentation..."

# 2. Run the actual tool.
if command -v sphinx-build &> /dev/null; then
    sphinx-build . _build
else
    echo "Warning: sphinx-build not found. Creating a placeholder _build directory."
    mkdir -p _build
    echo "<h1>Cryptoki Docs Placeholder</h1><p>Documentation tool not found in environment.</p>" > _build/index.html
fi

# 3. Fallback for CI/Bazel Run
if [ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]; then
  echo "Copying _build to workspace root: $BUILD_WORKSPACE_DIRECTORY"
  # Use -f to overwrite and -r for the directory
  cp -rf _build "$BUILD_WORKSPACE_DIRECTORY/"
fi
