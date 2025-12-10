#!/bin/bash

# Check if file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <input-file>"
    exit 1
fi

file="$1"

while IFS="--" read -r url _; do
    # Trim spaces
    url=$(echo "$url" | xargs)

    # Remove protocol
    clean=$(echo "$url" | sed -E 's~https?://~~; s~http://~~')

    # Remove everything after first slash
    host=$(echo "$clean" | cut -d'/' -f1)

    # Print host only if not empty
    [ -n "$host" ] && echo "$host"

done < "$file"

