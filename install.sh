#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# 1. Build the project
echo "Building project with Cargo..."
cargo build --release

# 2. Prepare the binary directory
# Using ~/.local/bin as it is the standard for user-space binaries
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"

echo "Installing binary to $BIN_DIR..."
cp target/release/mfs "$BIN_DIR/mfs"

# 3. Create systemd user directory if it doesn't exist
UNIT_DIR="$HOME/.config/systemd/user"
mkdir -p "$UNIT_DIR"

# 4. Create the Socket Unit
echo "Creating systemd socket unit..."
cat <<EOF > "$UNIT_DIR/keyserver.socket"
[Unit]
Description=Unix socket for KeyServer daemon

[Socket]
ListenStream=/run/user/%U/mfs/keyserver.sock
SocketMode=0600

[Install]
WantedBy=sockets.target
EOF

# 5. Create the Service Unit
echo "Creating systemd service unit..."
cat <<EOF > "$UNIT_DIR/keyserver.service"
[Unit]
Description=KeyServer Daemon
Requires=keyserver.socket
After=keyserver.socket

[Service]
Type=simple
ExecStart=$BIN_DIR/mfs
EOF

# 6. Activation
echo "Reloading systemd and starting socket..."
systemctl --user daemon-reload

# Stop service in case it's running, then start the socket
systemctl --user stop keyserver.service || true
systemctl --user enable --now keyserver.socket

echo "-------------------------------------------------------"
echo "Success! The socket is now listening."
echo "The daemon will start automatically when the socket is accessed."
echo "Socket path: /run/user/$(id -u)/mfs/keyserver.sock"
