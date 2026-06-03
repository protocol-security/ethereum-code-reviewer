#!/bin/bash

# Sync consensus specs from ethereum/consensus-specs repository
# This fetches the latest specs folder and syncs it to docs/consensus/specs

set -e  # Exit on error

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
TARGET_DIR="$ROOT_DIR/docs/consensus/specs"
TEMP_DIR="/tmp/consensus-specs-sync-$$"

echo "Syncing consensus specs from ethereum/consensus-specs..."

# Clone with sparse checkout (only specs folder)
echo "Fetching latest specs from upstream..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/ethereum/consensus-specs.git "$TEMP_DIR"
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

echo "Consensus specs synced successfully!"
echo "Location: $TARGET_DIR"
