#!/bin/bash

# Sync devp2p specs from ethereum/devp2p repository
# This fetches the latest devp2p folder and syncs it to docs/execution/specs

set -e  # Exit on error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
TARGET_DIR="$ROOT_DIR/docs/execution/specs"
TEMP_DIR="/tmp/execution-specs-sync-$$"

echo "Syncing devp2p specs from ethereum/devp2p..."

# Clone with sparse checkout (only devp2p folder)
echo "Fetching latest devp2p specs from upstream..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/ethereum/devp2p.git "$TEMP_DIR"
cd "$TEMP_DIR"
git sparse-checkout set specs

# Sync to target directory
echo "Syncing to $TARGET_DIR..."
rsync -av --delete specs/ "$TARGET_DIR/"

# Remove .pages file (not useful)
rm -f "$TARGET_DIR/.pages"

# Cleanup
echo "🧹 Cleaning up temporary files..."
rm -rf "$TEMP_DIR"

echo "devp2p specs synced successfully!"
echo "Location: $TARGET_DIR"
