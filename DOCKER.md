# Docker Setup for Zypher

To simplify the build and testing process for Zypher, you can use Docker to create an isolated environment. This ensures that all dependencies and configurations are consistent and do not interfere with your host machine.

## Prerequisites

- Docker installed on your system
- Docker Compose installed

## Using the Docker Development Shell

The `docker.sh` script provides the easiest way to work with the Zypher codebase inside a Docker container. It handles all the Docker container management for you.

### Basic Usage

```bash
./docker.sh
```

This will:
1. Start the Zypher container if it's not already running
2. Attach your current terminal to the container's bash shell
3. Allow you to run any commands directly inside the container

Once inside the container, you can run any make commands directly:

```bash
# Build everything
make

# Build just the encoder
make encoder

# Build just the loader
make loader

# Run tests
make test
```

To exit the container shell, simply type `exit`.

### Advanced Usage

#### Force Rebuild

If you need to rebuild the Docker image (e.g., after Dockerfile changes):

```bash
./docker.sh --rebuild
```

#### Run Single Commands

Run a specific command in the container without staying in the shell:

```bash
./docker.sh make
./docker.sh make encoder
./docker.sh make test
```

## Notes

- The Docker setup mounts your project directory to `/zypher` inside the container
- Any files you modify inside the container will be reflected on your host system
- The container remains running in the background after you exit the shell
- Your build artifacts will persist between shell sessions

## Troubleshooting

If you encounter any issues with the container:

1. Try forcing a rebuild: `./docker.sh --rebuild`
2. Check Docker daemon status
3. Verify Docker Compose is installed correctly