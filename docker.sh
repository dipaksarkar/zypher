#!/bin/bash
# docker.sh - Attach to Zypher Docker container or start it if needed

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker before continuing."
    exit 1
fi

# Set CONTAINER_NAME
CONTAINER_NAME="zypher-dev"

# Check if container exists and is running
RUNNING_CONTAINER=$(docker ps -q -f name=$CONTAINER_NAME)
EXISTING_CONTAINER=$(docker ps -a -q -f name=$CONTAINER_NAME)

# Parse command line arguments
COMMAND="${@:1}"
if [[ -z "$COMMAND" ]]; then
    COMMAND="bash"
fi

# If container exists but is not running, start it
if [[ -z "$RUNNING_CONTAINER" && -n "$EXISTING_CONTAINER" ]]; then
    echo "Starting existing Zypher Docker container..."
    docker start $CONTAINER_NAME
    
    # Run verification script to make sure environment is set up
    docker exec $CONTAINER_NAME bash -c "if [ ! -f /etc/profile.d/php-embed-env.sh ]; then /usr/local/bin/docker-setup.sh; fi"
    docker exec $CONTAINER_NAME bash -c "test -f /etc/profile.d/php-embed-env.sh && echo '✅ Environment file exists' || echo '❌ Environment file missing!'"
# If container doesn't exist, create and start it
elif [[ -z "$EXISTING_CONTAINER" ]]; then
    echo "Creating and starting Zypher Docker container..."
    docker-compose up -d
    
    # Wait for container to be fully up and verify environment setup
    sleep 2
    docker exec $CONTAINER_NAME bash -c "/usr/local/bin/docker-setup.sh"
    
    # Check if environment file exists after setup
    docker exec $CONTAINER_NAME bash -c "test -f /etc/profile.d/php-embed-env.sh && echo '✅ Environment file exists' || echo '❌ Environment file missing!'"
fi

# Execute the command in the container
echo "Executing in container: $COMMAND"
docker exec -it $CONTAINER_NAME bash -c "source /etc/profile.d/php-embed-env.sh 2>/dev/null || echo '⚠️ Warning: Could not source environment file'; $COMMAND"

# Check last exit status
if [ $? -ne 0 ]; then
    echo "⚠️ Command execution failed! Verifying container environment..."
    docker exec $CONTAINER_NAME bash -c "ls -la /etc/profile.d/ | grep php-embed-env.sh || echo '❌ Environment file missing!'"
    docker exec $CONTAINER_NAME bash -c "if [ ! -f /etc/profile.d/php-embed-env.sh ]; then echo '🔧 Attempting to fix by running setup script...'; /usr/local/bin/docker-setup.sh; fi"
fi