#!/bin/bash

# Production Deployment Script for Baileys WhatsApp API v7
# Handles Node.js version check, dependencies, and PM2 deployment

echo "========================================"
echo "  Baileys WhatsApp API - Deployment"
echo "========================================"
echo ""

# Required Node.js version for Baileys v7
REQUIRED_NODE_MAJOR=20

# Function to check Node.js version
check_node_version() {
    if ! command -v node &> /dev/null; then
        echo "Node.js is not installed!"
        return 1
    fi

    NODE_VERSION=$(node -v | cut -d'v' -f2)
    NODE_MAJOR=$(echo $NODE_VERSION | cut -d'.' -f1)

    echo "Current Node.js version: v$NODE_VERSION"

    if [ "$NODE_MAJOR" -lt "$REQUIRED_NODE_MAJOR" ]; then
        echo "Node.js $REQUIRED_NODE_MAJOR+ is required for Baileys v7"
        return 1
    fi

    echo "Node.js version OK"
    return 0
}

# Function to upgrade Node.js using nvm
upgrade_node_nvm() {
    echo "Attempting to upgrade Node.js using nvm..."

    # Source nvm if available
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

    if command -v nvm &> /dev/null; then
        echo "Installing Node.js 20 via nvm..."
        nvm install 20
        nvm use 20
        nvm alias default 20
        echo "Node.js upgraded successfully!"
        return 0
    else
        echo "nvm not found. Installing nvm first..."
        curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

        # Source nvm
        export NVM_DIR="$HOME/.nvm"
        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

        if command -v nvm &> /dev/null; then
            nvm install 20
            nvm use 20
            nvm alias default 20
            echo "Node.js 20 installed via nvm!"
            return 0
        else
            echo "Failed to install nvm. Please install Node.js 20+ manually."
            return 1
        fi
    fi
}

# Step 1: Check Node.js version
echo ""
echo "Step 1: Checking Node.js version..."
echo "-----------------------------------"

if ! check_node_version; then
    echo ""
    echo "Node.js 20+ is required. Attempting automatic upgrade..."
    upgrade_node_nvm

    # Re-check after upgrade
    if ! check_node_version; then
        echo ""
        echo "Failed to upgrade Node.js automatically."
        echo "Please upgrade manually:"
        echo "  nvm install 20 && nvm use 20"
        echo "Or visit: https://nodejs.org/"
        exit 1
    fi
fi

# Step 2: Check PM2
echo ""
echo "Step 2: Checking PM2..."
echo "-----------------------"
if ! command -v pm2 &> /dev/null; then
    echo "PM2 not found. Installing PM2 globally..."
    npm install -g pm2
fi
echo "PM2 is available"

# Step 3: Create necessary directories
echo ""
echo "Step 3: Creating directories..."
echo "-------------------------------"
mkdir -p logs
mkdir -p media
mkdir -p auth_info_baileys
mkdir -p activity_logs
mkdir -p sessions
echo "Directories created"

# Step 4: Clean install dependencies
echo ""
echo "Step 4: Installing dependencies..."
echo "----------------------------------"

# Remove node_modules for clean install if --clean flag passed
if [ "$1" == "--clean" ]; then
    echo "Cleaning node_modules for fresh install..."
    rm -rf node_modules
    rm -f package-lock.json
fi

# Install dependencies
npm install --production
echo "Dependencies installed"

# Step 5: Stop existing PM2 process
echo ""
echo "Step 5: Managing PM2 processes..."
echo "---------------------------------"
pm2 stop wa 2>/dev/null || true
pm2 delete wa 2>/dev/null || true
echo "Old processes stopped"

# Step 6: Set environment and start
echo ""
echo "Step 6: Starting application..."
echo "-------------------------------"
export NODE_ENV=production
export NODE_OPTIONS="--max-old-space-size=1024"

# Start with PM2
pm2 start ecosystem.config.js

# Save PM2 configuration
pm2 save

# Step 7: Show status
echo ""
echo "========================================"
echo "  Deployment Completed Successfully!"
echo "========================================"
echo ""
pm2 status
echo ""
echo "Useful commands:"
echo "  pm2 logs wa        - View application logs"
echo "  pm2 restart wa     - Restart application"
echo "  pm2 stop wa        - Stop application"
echo "  pm2 monit          - Monitor resources"
echo ""
echo "Application URL: http://baileys.teyu1000.odns.fr/"
echo ""
