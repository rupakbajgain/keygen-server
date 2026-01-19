#!/bin/bash

# 1. Define paths
UNIT_DIR="$HOME/.config/systemd/user"
BIN_DIR="$HOME/.local/bin"

echo "Stopping and disabling KeyServer units..."

# 2. Stop the service and the socket
# We stop the service first, then the socket listener.
systemctl --user stop keyserver.service || true
systemctl --user stop keyserver.socket || true

# 3. Disable the socket so it doesn't start on login
systemctl --user disable keyserver.socket || true

# 4. Remove the systemd unit files
echo "Removing unit files..."
rm -f "$UNIT_DIR/keyserver.socket"
rm -f "$UNIT_DIR/keyserver.service"

# 5. Reload systemd to apply the removal
systemctl --user daemon-reload
systemctl --user reset-failed

# 6. Optional: Remove the binary
# Uncomment the next line if you want to delete the binary from .local/bin as well
# rm -f "$BIN_DIR/mfs"

echo "-------------------------------------------------------"
echo "Uninstall complete."
echo "The socket /run/user/$(id -u)/mfs/keyserver.sock has been removed."
