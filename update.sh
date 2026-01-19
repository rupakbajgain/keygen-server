#!/bin/bash
set -e

# 1. Build
echo "Building..."
cargo build --release

# 2. Stop the service to unlock the file
# We use || true so the script doesn't crash if the service wasn't running
echo "Stopping service to unlock binary..."
systemctl --user stop keyserver.service || true

# 3. Update the binary
BIN_DIR="$HOME/.local/bin"
echo "Installing new binary..."
cp target/release/mfs "$BIN_DIR/mfs"

# 4. Refresh and Restart Socket
echo "Reloading systemd..."
systemctl --user daemon-reload
systemctl --user restart keyserver.socket

echo "Update successful! The new binary will load on the next request."
