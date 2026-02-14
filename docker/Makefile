# Purple Team GRC - Docker Makefile
# Convenience commands for Docker operations

.PHONY: help build up down logs restart clean backup restore shell-api shell-db

help:
	@echo "Purple Team GRC - Docker Commands"
	@echo ""
	@echo "  make build       - Build all containers"
	@echo "  make up          - Start all services"
	@echo "  make down        - Stop all services"
	@echo "  make logs        - View logs (follow mode)"
	@echo "  make restart     - Restart all services"
	@echo "  make clean       - Stop and remove all containers and volumes"
	@echo "  make backup      - Backup PostgreSQL database"
	@echo "  make restore     - Restore PostgreSQL database from backup.sql"
	@echo "  make shell-api   - Open shell in API container"
	@echo "  make shell-db    - Open PostgreSQL shell"
	@echo ""

build:
	docker-compose build

up:
	docker-compose up -d
	@echo ""
	@echo "Services started! Access:"
	@echo "  API Server: http://localhost:8443/health"
	@echo ""
	@echo "View logs with: make logs"

down:
	docker-compose down

logs:
	docker-compose logs -f

restart: down up

clean:
	docker-compose down -v
	@echo "Warning: All data has been removed!"

backup:
	docker-compose exec postgres pg_dump -U purpleteam purpleteam > backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "Backup created: backup_$(shell date +%Y%m%d_%H%M%S).sql"

restore:
	@echo "Restoring from backup.sql..."
	cat backup.sql | docker-compose exec -T postgres psql -U purpleteam purpleteam
	@echo "Restore complete!"

shell-api:
	docker-compose exec api /bin/bash

shell-db:
	docker-compose exec postgres psql -U purpleteam -d purpleteam
