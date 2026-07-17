#!/bin/sh

USER_NAME="${HEADSCALE_USER:-default}"
SERVER_URL="${HEADSCALE_SERVER_URL:-}"

# Function to generate a random 32 character string
generate_random_string() {
  tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32
}

# Check if cookie_secret line exists and is empty
if grep -q '^\([[:space:]]*\)cookie_secret:[[:space:]]*$' /headplane-config.yaml; then
  echo "Cookie secret not found, generating..."
  
  COOKIE_SECRET=$(generate_random_string)
  
  if [ -z "$COOKIE_SECRET" ]; then
    echo "ERROR: Failed to generate cookie secret"
    exit 1
  fi
  
  echo "Cookie secret generated"
  
  # Update the cookie_secret line
  sed 's|^\([[:space:]]*\)cookie_secret:[[:space:]]*$|\1cookie_secret: "'"$COOKIE_SECRET"'"|' /headplane-config.yaml > /tmp/headplane-config.yaml.tmp
  
  # Replace the original file
  cat /tmp/headplane-config.yaml.tmp > /headplane-config.yaml
  rm /tmp/headplane-config.yaml.tmp
  
  echo "Cookie secret added to headplane-config.yaml"
else
  echo "Cookie secret already exists in headplane-config.yaml, skipping generation"
fi

# Check if pre_authkey line exists and is empty
if grep -q '^\([[:space:]]*\)pre_authkey:[[:space:]]*$' /headplane-config.yaml; then
  echo "Pre-auth key not found in agent config, generating..."
  
  # Create user
  echo "Creating user '$USER_NAME'..."
  docker exec headscale headscale users create "$USER_NAME" 2>/dev/null || echo "User '$USER_NAME' already exists"
  
  # Generate pre-auth key
  echo "Generating headplane pre-auth key for user ID 1..."
  OUTPUT=$(docker exec headscale headscale preauthkeys create --user 1 90d 2>&1)
  PREAUTH_KEY=$(echo "$OUTPUT" | tail -n1 | tr -d '\r\n' | xargs)  
  
  OUTPUT=$(docker exec headscale headscale preauthkeys create --user 1 --reusable --ephemeral --expiration 90d)
  EPHEMERAL_KEY=$(echo "$OUTPUT" | tail -n1 | tr -d '\r\n' | xargs)
  echo "Generated ephemeral node join key $EPHEMERAL_KEY" 
  
  
  if [ -z "$PREAUTH_KEY" ]; then
    echo "ERROR: Failed to generate pre-auth key"
    echo "Output was:"
    echo "$OUTPUT"
    exit 1
  fi
  
  echo "Pre-auth key generated: $PREAUTH_KEY"
  
  # Update only the pre_authkey line
  sed 's|^\([[:space:]]*\)pre_authkey:[[:space:]]*$|\1pre_authkey: "'"$PREAUTH_KEY"'"|' /headplane-config.yaml > /tmp/headplane-config.yaml.tmp
  
  # Replace the original file
  cat /tmp/headplane-config.yaml.tmp > /headplane-config.yaml
  rm /tmp/headplane-config.yaml.tmp
  
  echo "Pre-auth key added to headplane-config.yaml"
else
  echo "Pre-auth key already exists in headplane-config.yaml, skipping generation"
fi

# Sync and restart
sync

POLICY_FILE="/policy.json"  

# Try to fetch current policy; ignore output, capture exit status.
if headscale policy get >/dev/null 2>&1; then
    # Success: a policy already exists (or GetPolicy returns OK) -> do nothing
    exit 0
else
    # Error: no policy set / GetPolicy failed -> apply your policy
    echo "No policy in database. Applying policy from: $POLICY_FILE"
    docker exec headscale headscale policy set --file "$POLICY_FILE"
    echo "Policy applied."
fi


echo "Initialization complete"