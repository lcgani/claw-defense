#!/bin/bash
set -e

echo "Setting up Claw Defense..."

if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "Please update .env with your credentials"
fi

echo "Starting Elasticsearch and Kibana..."
docker-compose up -d

echo "Waiting for Elasticsearch to be ready..."
until curl -s http://localhost:9200 > /dev/null; do
    sleep 2
done

echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Setup complete!"
echo "Elasticsearch: http://localhost:9200"
echo "Kibana: http://localhost:5601"
