#!/bin/bash
# Setup script for PHP embedding environment variables

set -e  # Exit immediately if a command fails

echo "Starting PHP embed environment setup..."

# Create config directories if they don't exist
mkdir -p /etc/profile.d
echo "Created /etc/profile.d directory"

# Set up the environment file
cat > /etc/profile.d/php-embed-env.sh << 'EOL'
#!/bin/bash

# Library paths
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Include paths for PHP embed
export PHP_EMBED_INCLUDE=/usr/local/include/php
export C_INCLUDE_PATH=/usr/local/include/php:/usr/local/include/php/main:/usr/local/include/php/Zend:/usr/local/include/php/TSRM:$C_INCLUDE_PATH
export CPLUS_INCLUDE_PATH=/usr/local/include/php:/usr/local/include/php/main:/usr/local/include/php/Zend:/usr/local/include/php/TSRM:$CPLUS_INCLUDE_PATH

# Force PHP embedding detection
export HAVE_EMBED=1
export IN_DOCKER=yes

echo "PHP embedding environment variables set:"
echo "PHP_EMBED_INCLUDE: $PHP_EMBED_INCLUDE"
echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
EOL

echo "Created environment file at /etc/profile.d/php-embed-env.sh"

# Make the script executable
chmod +x /etc/profile.d/php-embed-env.sh
echo "Made environment file executable"

# Apply the environment variables now
if [ -f /etc/profile.d/php-embed-env.sh ]; then
  source /etc/profile.d/php-embed-env.sh
  echo "Sourced environment file successfully"
else
  echo "ERROR: Environment file doesn't exist after creation!"
  exit 1
fi

# Also update .bashrc for interactive sessions if it doesn't already contain the source line
if [ -f /root/.bashrc ]; then
  grep -q "source /etc/profile.d/php-embed-env.sh" /root/.bashrc || echo "source /etc/profile.d/php-embed-env.sh" >> /root/.bashrc
  echo "Updated .bashrc to source environment file"
fi

# Verify PHP embed SAPI is available
echo "Verifying PHP embed SAPI installation:"
if [ -f "/usr/local/lib/libphp.so" ]; then
  echo "✅ Found libphp.so"
  ls -la /usr/local/lib/libphp*
  echo "Library search paths:"
  ldconfig -p | grep php
else
  echo "❌ ERROR: libphp.so not found!"
  ls -la /usr/local/lib/ | grep php
  echo "This might cause problems with PHP embedding"
fi

echo "PHP include paths:"
if [ -f "/usr/local/include/php/Zend/zend.h" ]; then
  echo "✅ Found zend.h at /usr/local/include/php/Zend/zend.h"
else
  echo "❌ ERROR: zend.h not found in PHP include path!"
  echo "Checking for Zend headers:"
  find /usr/local/include -name "zend.h"
fi

# Directory structure validation
echo "Checking Zypher directory structure..."
if [ -d "/zypher/encoder" ] && [ -d "/zypher/loader" ]; then
  echo "✅ Zypher encoder and loader directories found"
else
  echo "❌ WARNING: Zypher directory structure incomplete"
  echo "Current directory contents:"
  ls -la /zypher
fi

# Create a verification file to check if setup was completed
echo "PHP_EMBED_SETUP_COMPLETE=true" > /tmp/php-embed-setup-verified
echo "Setup script completed successfully"