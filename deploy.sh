#!/bin/bash

# Production Deployment Script for o2switch/cPanel
# This script helps deploy the Baileys WhatsApp API

echo "🚀 Starting production deployment..."

# Check if PM2 is installed
if ! command -v pm2 &> /dev/null; then
    echo "❌ PM2 is not installed. Please install it first:"
    echo "npm install -g pm2"
    exit 1
fi

# Create necessary directories
mkdir -p logs
mkdir -p media
mkdir -p session_auth_info
mkdir -p activity_logs
mkdir -p sessions

# Install dependencies with bcrypt compatibility
echo "📦 Installing dependencies for cPanel/o2switch..."
echo "   Using smart installer for bcrypt compatibility..."
npm run install:smart

# Stop existing PM2 process
echo "🛑 Stopping existing processes..."
pm2 stop wa 2>/dev/null || true
pm2 delete wa 2>/dev/null || true

# Start with PM2
echo "▶️ Starting application with PM2..."
pm2 start ecosystem.config.js

# Save PM2 configuration
pm2 save

# Show status
echo "✅ Deployment completed!"
echo ""
echo "📊 Application Status:"
pm2 status

echo ""
echo "📝 Useful commands:"
echo "  pm2 logs wa     - View application logs"
echo "  pm2 restart wa  - Restart application"
echo "  pm2 stop wa     - Stop application"
echo "  pm2 status      - Check status"
echo ""
echo "🌐 Your application should be available at:"
echo "  http://baileys.teyu1000.odns.fr/"