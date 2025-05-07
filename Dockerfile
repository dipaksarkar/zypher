FROM debian:bullseye

ARG PHP_VERSION=8.3
ENV PHP_VERSION=${PHP_VERSION}

# Install base dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    ca-certificates \
    lsb-release \
    apt-transport-https \
    zlib1g-dev \
    libxml2-dev \
    libsqlite3-dev \
    libpng-dev \
    libjpeg-dev \
    libonig-dev \
    libcurl4-openssl-dev \
    bison \
    re2c \
    unzip \
    gnupg2 \
    libzip-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and build PHP with embed SAPI
WORKDIR /tmp

# Use specific PHP version (8.3.20 instead of just 8.3)
RUN set -eux; \
    PHP_FULL_VERSION="8.3.20"; \
    echo "Downloading PHP ${PHP_FULL_VERSION}"; \
    wget -q "https://www.php.net/distributions/php-${PHP_FULL_VERSION}.tar.gz" && \
    tar -xzf "php-${PHP_FULL_VERSION}.tar.gz" && \
    cd "php-${PHP_FULL_VERSION}" && \
    # Configure PHP with embed SAPI and required extensions
    ./configure \
    --prefix=/usr/local \
    --enable-embed=shared \
    --enable-fpm \
    --with-fpm-user=www-data \
    --with-fpm-group=www-data \
    --with-openssl \
    --with-zlib \
    --with-curl \
    --enable-mbstring \
    --enable-opcache \
    --with-mysqli \
    --enable-pcntl \
    --with-zip \
    --with-pdo-mysql \
    && \
    # Build and install PHP
    make -j$(nproc) && \
    make install && \
    # Create symbolic links for the embed library and header files
    mkdir -p /usr/local/include/php && \
    ln -sf /usr/local/include/php /usr/include/php && \
    mkdir -p /usr/lib/php && \
    ln -sf /usr/local/lib/libphp.so /usr/lib/libphp.so && \
    # Configure dynamic linker with embed library path
    echo "/usr/local/lib" > /etc/ld.so.conf.d/php-embed.conf && \
    ldconfig && \
    # Clean up
    cd /tmp && \
    rm -rf "php-${PHP_FULL_VERSION}" "php-${PHP_FULL_VERSION}.tar.gz"

# Install Composer for PHP package management
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Configure PHP
RUN mkdir -p /usr/local/etc/php && \
    echo "memory_limit = 512M" > /usr/local/etc/php/php.ini && \
    echo "opcache.enable=1" >> /usr/local/etc/php/php.ini && \
    echo "opcache.enable_cli=1" >> /usr/local/etc/php/php.ini

# Set working directory
WORKDIR /zypher

# Environment variables for build process
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV C_INCLUDE_PATH=/usr/local/include/php:$C_INCLUDE_PATH
ENV CPLUS_INCLUDE_PATH=/usr/local/include/php:$CPLUS_INCLUDE_PATH
ENV PATH=/usr/local/bin:$PATH
ENV PHP_EMBED_INCLUDE=/usr/local/include/php

# Copy Zypher source code
COPY . /zypher

# Default command
CMD ["make"]