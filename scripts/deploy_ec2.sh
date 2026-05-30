#!/usr/bin/env bash
set -euo pipefail

HOST="${SLOPTUNNEL_EC2_HOST:-18.219.84.252}"
USER_NAME="${SLOPTUNNEL_EC2_USER:-ubuntu}"
KEY="${SLOPTUNNEL_EC2_KEY:-keys/sloptunnel-ec2.pem}"
PORTS="${SLOPTUNNEL_PORTS:-auto}"
TRANSPORT="${SLOPTUNNEL_TRANSPORT:-both}"
MAX_AUTO_PORTS="${SLOPTUNNEL_MAX_AUTO_PORTS:-65535}"
TOKEN="${SLOPTUNNEL_TOKEN:-change-me}"
REMOTE_DIR="${SLOPTUNNEL_REMOTE_DIR:-/home/ubuntu/sloptunnel}"
USE_SUDO="${SLOPTUNNEL_USE_SUDO:-1}"
LOCAL_TOKEN_FILE="$(mktemp)"
trap 'rm -f "$LOCAL_TOKEN_FILE"' EXIT

printf '%s\n' "$TOKEN" > "$LOCAL_TOKEN_FILE"
chmod 600 "$LOCAL_TOKEN_FILE"

make

ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
  "mkdir -p '$REMOTE_DIR'"

if [[ "$USE_SUDO" == "1" ]]; then
  ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
    "sudo pkill -x sloptunnel >/dev/null 2>&1 || true; sleep 1"
else
  ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
    "pkill -x sloptunnel >/dev/null 2>&1 || true; sleep 1"
fi

scp -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  build/sloptunnel "$USER_NAME@$HOST:$REMOTE_DIR/sloptunnel.tmp"

ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
  "mv '$REMOTE_DIR/sloptunnel.tmp' '$REMOTE_DIR/sloptunnel'"

scp -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
  "$LOCAL_TOKEN_FILE" "$USER_NAME@$HOST:$REMOTE_DIR/token"

ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
  "chmod 600 '$REMOTE_DIR/token'"

if [[ "$USE_SUDO" == "1" ]]; then
  ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
    "sudo sh -c 'ulimit -n 200000 || ulimit -n 65535 || true; \
     nohup \"$REMOTE_DIR/sloptunnel\" --server --transport \"$TRANSPORT\" --ports \"$PORTS\" \
     --max-auto-ports \"$MAX_AUTO_PORTS\" --token-file \"$REMOTE_DIR/token\" --headless \
     > \"$REMOTE_DIR/server.log\" 2>&1 &'"
else
  ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$USER_NAME@$HOST" \
    "(ulimit -n 200000 || ulimit -n 65535 || true; \
     nohup '$REMOTE_DIR/sloptunnel' --server --transport '$TRANSPORT' --ports '$PORTS' \
     --max-auto-ports '$MAX_AUTO_PORTS' --token-file '$REMOTE_DIR/token' --headless \
     > '$REMOTE_DIR/server.log' 2>&1 &)"
fi

echo "sloptunnel server started on $HOST transport $TRANSPORT ports $PORTS"
