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

# Use specific PHP version and explicitly verify embed SAPI
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
    # Save a copy of the PHP source directory for header access
    mkdir -p /usr/local/src && \
    cp -R /tmp/php-${PHP_FULL_VERSION} /usr/local/src/php-src && \
    # Create symbolic links for Zend headers - this is critical
    mkdir -p /usr/local/include/php/Zend && \
    mkdir -p /usr/local/include/php/main && \
    mkdir -p /usr/local/include/php/TSRM && \
    mkdir -p /usr/local/include/php/ext && \
    cp -R /usr/local/src/php-src/Zend/*.h /usr/local/include/php/Zend/ && \
    cp -R /usr/local/src/php-src/main/*.h /usr/local/include/php/main/ && \
    cp -R /usr/local/src/php-src/TSRM/*.h /usr/local/include/php/TSRM/ && \
    # Create symlinks for all subdirectories needed for compilation
    ln -sf /usr/local/include/php /usr/include/php && \
    mkdir -p /usr/lib/php && \
    ln -sf /usr/local/lib/libphp.so /usr/lib/libphp.so && \
    # Configure dynamic linker with embed library path
    echo "/usr/local/lib" > /etc/ld.so.conf.d/php-embed.conf && \
    ldconfig && \
    # Verify that PHP embed SAPI is properly installed
    echo "Verifying PHP embed SAPI installation:" && \
    ls -la /usr/local/lib/libphp* && \
    # Clean up
    cd /tmp && \
    rm -rf "php-${PHP_FULL_VERSION}.tar.gz"

# Install Composer for PHP package management
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Configure PHP
RUN mkdir -p /usr/local/etc/php && \
    echo "memory_limit = 512M" > /usr/local/etc/php/php.ini && \
    echo "opcache.enable=1" >> /usr/local/etc/php/php.ini && \
    echo "opcache.enable_cli=1" >> /usr/local/etc/php/php.ini

# Set working directory
WORKDIR /zypher

# Environment variables setup (these are available at build time)
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    PHP_EMBED_INCLUDE=/usr/local/include/php \
    C_INCLUDE_PATH=/usr/local/include/php:/usr/local/include/php/main:/usr/local/include/php/Zend:/usr/local/include/php/TSRM:$C_INCLUDE_PATH \
    CPLUS_INCLUDE_PATH=/usr/local/include/php:/usr/local/include/php/main:/usr/local/include/php/Zend:/usr/local/include/php/TSRM:$CPLUS_INCLUDE_PATH \
    HAVE_EMBED=1 \
    IN_DOCKER=yes

# Copy setup script and make it executable
COPY docker-setup.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-setup.sh

# Copy project files after environment setup
COPY . /zypher

# Create a robust entrypoint script
RUN echo '#!/bin/bash' > /usr/local/bin/entrypoint.sh && \
    echo '' >> /usr/local/bin/entrypoint.sh && \
    echo '# Create environment file if it does not exist' >> /usr/local/bin/entrypoint.sh && \
    echo 'if [ ! -f "/etc/profile.d/php-embed-env.sh" ]; then' >> /usr/local/bin/entrypoint.sh && \
    echo '  echo "Environment file does not exist, running setup script..."' >> /usr/local/bin/entrypoint.sh && \
    echo '  /usr/local/bin/docker-setup.sh' >> /usr/local/bin/entrypoint.sh && \
    echo 'fi' >> /usr/local/bin/entrypoint.sh && \
    echo '' >> /usr/local/bin/entrypoint.sh && \
    echo '# Source environment file with error handling' >> /usr/local/bin/entrypoint.sh && \
    echo 'if [ -f "/etc/profile.d/php-embed-env.sh" ]; then' >> /usr/local/bin/entrypoint.sh && \
    echo '  echo "Sourcing PHP embed environment variables..."' >> /usr/local/bin/entrypoint.sh && \
    echo '  source /etc/profile.d/php-embed-env.sh' >> /usr/local/bin/entrypoint.sh && \
    echo 'else' >> /usr/local/bin/entrypoint.sh && \
    echo '  echo "WARNING: Environment file still does not exist!"' >> /usr/local/bin/entrypoint.sh && \
    echo '  echo "Setting environment variables manually..."' >> /usr/local/bin/entrypoint.sh && \
    echo '  export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH' >> /usr/local/bin/entrypoint.sh && \
    echo '  export PHP_EMBED_INCLUDE=/usr/local/include/php' >> /usr/local/bin/entrypoint.sh && \
    echo '  export C_INCLUDE_PATH=/usr/local/include/php:/usr/local/include/php/main:/usr/local/include/php/Zend:/usr/local/include/php/TSRM:$C_INCLUDE_PATH' >> /usr/local/bin/entrypoint.sh && \
    echo '  export CPLUS_INCLUDE_PATH=/usr/local/include/php:/usr/local/include/php/main:/usr/local/include/php/Zend:/usr/local/include/php/TSRM:$CPLUS_INCLUDE_PATH' >> /usr/local/bin/entrypoint.sh && \
    echo '  export HAVE_EMBED=1' >> /usr/local/bin/entrypoint.sh && \
    echo '  export IN_DOCKER=yes' >> /usr/local/bin/entrypoint.sh && \
    echo 'fi' >> /usr/local/bin/entrypoint.sh && \
    echo '' >> /usr/local/bin/entrypoint.sh && \
    echo '# Execute the command passed to docker run' >> /usr/local/bin/entrypoint.sh && \
    echo 'exec "$@"' >> /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]