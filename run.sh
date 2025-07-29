#!/usr/bin/env bash
set -euo pipefail

echo "Starting process..."

# Exit if no port number is provided
if [ "$#" -ne 1 ]; then
  echo "Parameter required PORT"
  exit 1
fi

PORT="$1"

# Exit if the port is not a non-negative integer
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
  echo "PORT must be a non-negative integer."
  exit 1
fi

# Kill any process currently using the specified port
if PIDS=$(timeout 2s lsof -ti ":$PORT"); then
  if [ -n "$PIDS" ]; then
    echo "Killing process on port $PORT..."
    kill $PIDS || kill -9 $PIDS
  fi
fi

# Update code from GitHub repo
if ! git pull; then
  echo "git pull failed"
  exit 1
fi

# Create virtual environment and install dependencies
uv venv
uv sync --frozen
if ! uv sync --frozen; then
  echo "uv sync failed"
  exit 1
fi
uv cache prune --ci


# Start the Flask app using Gunicorn on the specified port
uv run gunicorn -b ":$PORT" app:app