#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
build_dir="$repo_root/cpp/build"

if [[ ! -f "$repo_root/cpp/CMakeLists.txt" ]]; then
  echo "cpp/CMakeLists.txt not found"
  exit 1
fi

mkdir -p "$build_dir"
cd "$build_dir"
cmake .. >/dev/null
cmake --build . >/dev/null

if [[ -x "$build_dir/test_cpp" ]]; then
  "$build_dir/test_cpp"
fi
