#!/bin/bash

###########################################################
#
# This script waits for the Keycloak service to come up,
# logs into the admin REST API, and creates realm user(s).
#
# It is a workaround, because Keycloak cannot seem to
# directly import realm users into a usable state at this
# time.
#
###########################################################


# Keycloak origin from inside the Docker Compose network.
KEYCLOAK_ORIGIN="http://keycloak:8080"

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
# Generated user hash:
# - PBKDF2 HMAC SHA256
# - Salt as base64
# - Iterations: 27500
# - dkLen: 512
# https://8gwifi.org/pbkdf.jsp
USER_FILE="$SCRIPT_DIR/keycloak-realm-user-data.json"


function keycloak_admin_cli_login() {
    # Authenticate to the Keycloak admin CLI.
    USER="$1"
    PASSWORD="$2"
    CLIENT_ID="admin-cli"
    GRANT_TYPE="password"

    ACCESS_TOKEN=$(\
        curl -s \
        -d "client_id=$CLIENT_ID" \
        -d "username=$USER" \
        -d "password=$PASSWORD" \
        -d "grant_type=$GRANT_TYPE" \
        "$KEYCLOAK_ORIGIN/realms/master/protocol/openid-connect/token" \
        | sed -n 's|.*"access_token":"\([^"]*\)".*|\1|p'\
    )
    echo "$ACCESS_TOKEN"
}


function keycloak_create_realm_user() {
    ACCESS_TOKEN="$1"
    REALM="$2"

    # Create the user via Keycloak API.
    # https://www.keycloak.org/docs-api/18.0/rest-api/#_users_resource
    # https://www.keycloak.org/docs-api/18.0/rest-api/#_userrepresentation
    result=$(\
        curl -s -X POST \
        -H "Authorization: bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d @$USER_FILE \
        "$KEYCLOAK_ORIGIN/admin/realms/$REALM/users" \
    )

    if [ $? -eq 0 ]; then
        echo "Finished creating Keycloak user(s)";
    else
        echo "Failed to create Keycloak user(s)";
    fi
}


HEALTHCHECK_URL="$KEYCLOAK_ORIGIN/health/ready"
while : ; do
    echo "Waiting for Keycloak API to come up..."
    #echo "Running curl -s $HEALTHCHECK_URL"
    curl -s -I "$HEALTHCHECK_URL"
    if [ $? -eq 0 ]; then break; fi
    sleep 5;
done


echo "Keycloak is up. Creating user(s)..."
# Credentials need to match the Docker Compose values.
access_token=$(keycloak_admin_cli_login "admin" "password")
keycloak_create_realm_user "$access_token" "demo"
echo "Execution complete"
