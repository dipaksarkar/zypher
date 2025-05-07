# Docker Setup for Zypher

To simplify the build and testing process for Zypher, you can use Docker to create an isolated environment. This ensures that all dependencies and configurations are consistent and do not interfere with your host machine.

## Prerequisites

- Docker installed on your system
- Docker Compose installed (optional, for multi-container setups)

## Docker Instructions

### 1. Build the Docker Image

```bash
docker-compose build
```

This will create the Zypher Docker image with all the necessary dependencies installed.

### 2. Run Makefile Commands Using Docker Compose

The `docker-compose.yml` file has been configured to make it easy to run any Makefile command. Here are examples of common commands:

#### Build Everything (Default)

```bash
docker-compose up
```

This will build both the encoder and loader by running `make all`.

#### Build Specific Components

```bash
# Build just the encoder
docker-compose run --rm make encoder

# Build just the loader
docker-compose run --rm make loader

# Build debug version of the loader
docker-compose run --rm make debug_loader
```

#### Install the Extension

```bash
# Install the extension to PHP's extension directory
docker-compose run --rm make install
```

#### Test Commands

```bash
# Run all tests
docker-compose run --rm make test

# Run quick test
docker-compose run --rm make quick_test
```

#### Utility Commands

```bash
# Show system information
docker-compose run --rm make info

# Check PHP environment
docker-compose run --rm make check_php

# Clean build files
docker-compose run --rm make clean

# Deep clean (remove master key and build files)
docker-compose run --rm make distclean
```

### 3. Run the Encoder Directly

To use the encoder after building it:

```bash
docker-compose run --rm encoder -v
```

This will run the Zypher encoder command with the `-v` flag to show version information.

You can pass any arguments to the encoder:

```bash
docker-compose run --rm encoder -o output.php input.php
```

### 4. Interactive Development

For interactive development within the Docker container:

```bash
docker-compose run --rm shell
```

This will start a shell session in the container, where you can run any command manually.

## Mounting Volumes

The Docker setup mounts your project directory to `/zypher` inside the container. This means:

1. Any files you create in the container in the `/zypher` directory will be visible on your host machine.
2. Any changes you make on your host machine will be immediately reflected in the container.

## Notes

- The Docker image is based on `php:8.3-cli` and includes all necessary dependencies for building and running Zypher.
- The `Makefile` handles the build process for both the encoder and loader.
- The `zypher_master_key.h` file is generated during the build process and is required for both encoding and decoding.

## Troubleshooting

If you encounter any issues, ensure that:

- Docker is installed and running on your system.
- The `Makefile` is correctly configured for your environment.
- All required dependencies are installed in the Docker image.

For further assistance, refer to the `README.md` or contact the project maintainers.