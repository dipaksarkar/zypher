#!/bin/bash
# docker.sh - Attach to Zypher Docker container or start it if needed

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: Docker Compose is not installed or not in PATH"
    exit 1
fi

# Container name as defined in docker-compose.yml
CONTAINER_NAME="zypher"

# Ensure Docker daemon is running
docker info &>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: Docker daemon is not running. Please start Docker and try again."
    exit 1
fi

# Force rebuild container if specified
if [ "$1" == "--rebuild" ]; then
    echo "Force rebuilding Zypher Docker image..."
    docker-compose build --no-cache zypher
    if [ $? -ne 0 ]; then
        echo "Error: Failed to rebuild Docker image."
        exit 1
    fi
    shift
fi

# Function to ensure container exists and is running
ensure_container_running() {
    # Check if the container exists
    if ! docker ps -a -q -f name=$CONTAINER_NAME | grep -q .; then
        echo "Creating and starting Zypher container..."
        # Build the image first to ensure it exists
        docker-compose build zypher
        if [ $? -ne 0 ]; then
            echo "Error: Failed to build Docker image."
            return 1
        fi
        
        # Create and start the container
        docker-compose up -d zypher
        if [ $? -ne 0 ]; then
            echo "Error: Failed to create and start container."
            return 1
        fi
        
        echo "Waiting for container to fully initialize..."
        sleep 2
    elif ! docker ps -q -f name=$CONTAINER_NAME | grep -q .; then
        echo "Starting existing Zypher container..."
        docker start $CONTAINER_NAME
        if [ $? -ne 0 ]; then
            echo "Error: Failed to start container."
            return 1
        fi
        echo "Waiting for container to fully initialize..."
        sleep 2
    else
        echo "Zypher container is already running."
    fi
    
    return 0
}

# Check if we're supposed to run a command directly
if [ $# -gt 0 ]; then
    # Ensure the container is running
    ensure_container_running
    if [ $? -ne 0 ]; then
        echo "Failed to ensure container is running. Exiting."
        exit 1
    fi
    
    echo "Running command in container: $@"
    docker exec -it $CONTAINER_NAME "$@"
    exit $?
fi

# Otherwise, provide an interactive shell
ensure_container_running
if [ $? -ne 0 ]; then
    echo "Failed to ensure container is running. Exiting."
    exit 1
fi

echo "Attaching to Zypher container..."
docker exec -it $CONTAINER_NAME /bin/bash
if [ $? -ne 0 ]; then
    echo "Failed to attach to container. Trying to restart..."
    docker restart $CONTAINER_NAME
    sleep 2
    echo "Retrying container attachment..."
    docker exec -it $CONTAINER_NAME /bin/bash
    if [ $? -ne 0 ]; then
        echo "Error: Could not attach to container after restart."
        exit 1
    fi
fi

echo "Exited Zypher container shell"