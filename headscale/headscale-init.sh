#!/bin/ash

CONFIG_FILE="/headscale-config.yaml"
ENV_VAR="HEADSCALE_HOSTNAME"

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file $CONFIG_FILE not found"
    exit 1
fi

# Extract the server_url value from the YAML file
SERVER_URL=$(grep "^server_url:" "$CONFIG_FILE" | sed 's/^server_url:[[:space:]]*//' | tr -d '"' | tr -d "'")

# Check if server_url is empty or not set
if [ -z "$SERVER_URL" ]; then
    echo "server_url is empty or not set"
    
    # Check if environment variable is set
    if [ -z "$HEADSCALE_HOSTNAME" ]; then
        echo "Error: Environment variable $ENV_VAR is not set"
        exit 1
    fi
    
    echo "Setting server_url to: https://$HEADSCALE_HOSTNAME"
    
    # Update the config file - Docker volume compatible method
    TEMP_FILE=$(mktemp)
    sed "s|^server_url:.*|server_url: \"https://${HEADSCALE_HOSTNAME}\"|" "$CONFIG_FILE" > "$TEMP_FILE"
    cat "$TEMP_FILE" > "$CONFIG_FILE"
    rm "$TEMP_FILE"
    
    echo "Config file updated successfully"
else
    echo "server_url is already set to: $SERVER_URL"
fi

DERPMAP="/derpmap.yaml"
TMP="/tmp/${DERPMAP}"
awk -v h="$HEADSCALE_HOSTNAME" '
  # Match a hostname field that is empty:
  /^[[:space:]]*hostname:[[:space:]]*$/ {
      print "        hostname: " h
      next
  }
  { print }
' "$DERPMAP" > "$TMP" && cat "$TMP" > "$DERPMAP"