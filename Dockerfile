FROM php:8.3-cli

# Install required dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    && docker-php-ext-install opcache \
    && pecl install zendopcache || true

# Set working directory
WORKDIR /zypher

# Copy Zypher source code into the container
COPY . /zypher

# Build Zypher encoder and loader
RUN make