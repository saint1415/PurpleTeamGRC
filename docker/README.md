# Purple Team GRC - Docker Deployment Guide

This directory contains Docker containerization files for deploying Purple Team GRC in a multi-container environment with PostgreSQL backend.

## Quick Start

1. **Copy environment file:**
   ```bash
   cp docker/.env.example .env
   ```

2. **Edit `.env` and set your passwords and API keys:**
   ```bash
   POSTGRES_PASSWORD=your-secure-password
   NVD_API_KEY=your-nvd-api-key  # Optional but recommended
   PURPLE_API_KEYS=your-api-key-1,your-api-key-2
   ```

3. **Start all services:**
   ```bash
   docker-compose up -d
   ```

4. **Check service status:**
   ```bash
   docker-compose ps
   docker-compose logs -f
   ```

## Architecture

The Docker deployment consists of three containers:

### 1. PostgreSQL Database (`postgres`)
- **Image:** `postgres:16-alpine`
- **Port:** 5432
- **Volume:** `pgdata` (persistent storage)
- Automatically initializes schema from `docker/init-db.sql`

### 2. API Server (`api`)
- **Build:** Multi-stage Dockerfile (target: `api`)
- **Port:** 8443
- **Dependencies:** PostgreSQL
- RESTful API for findings, assets, remediation, risks
- Health check endpoint: `http://localhost:8443/health`

### 3. Background Worker (`scheduler`)
- **Build:** Multi-stage Dockerfile (target: `worker`)
- **Dependencies:** PostgreSQL
- Runs scheduled scans every minute
- NVD updates every 4 hours
- SLA breach notifications every 5 minutes
- Exception cleanup every hour

## Services

### Start Services
```bash
docker-compose up -d
```

### Stop Services
```bash
docker-compose down
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f scheduler
docker-compose logs -f postgres
```

### Rebuild After Code Changes
```bash
docker-compose build
docker-compose up -d
```

## API Endpoints

Once the API server is running, you can access:

- **Health Check:** `GET http://localhost:8443/health`
- **Findings:** `GET http://localhost:8443/api/v1/findings`
- **Assets:** `GET http://localhost:8443/api/v1/assets`
- **Remediation:** `GET http://localhost:8443/api/v1/remediation`
- **Risks:** `GET http://localhost:8443/api/v1/risks`
- **Sessions:** `GET http://localhost:8443/api/v1/sessions`
- **Statistics:** `GET http://localhost:8443/api/v1/stats`

### Authentication

Add one of these headers to your requests:

```bash
# Bearer token
curl -H "Authorization: Bearer your-api-key" http://localhost:8443/api/v1/findings

# API key header
curl -H "X-API-Key: your-api-key" http://localhost:8443/api/v1/findings
```

## Data Persistence

The following directories are mounted as volumes:

- `./data` → Container data (findings, evidence, logs)
- `./tools` → External tools (nmap, etc.)
- `./config` → Configuration files
- `pgdata` → PostgreSQL database (Docker volume)

## Database Management

### Access PostgreSQL Shell
```bash
docker-compose exec postgres psql -U purpleteam -d purpleteam
```

### Backup Database
```bash
docker-compose exec postgres pg_dump -U purpleteam purpleteam > backup.sql
```

### Restore Database
```bash
cat backup.sql | docker-compose exec -T postgres psql -U purpleteam purpleteam
```

### Reset Database (WARNING: Deletes all data)
```bash
docker-compose down -v
docker-compose up -d
```

## Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs api

# Check if port is already in use
netstat -an | grep 8443
```

### Database connection errors
```bash
# Verify PostgreSQL is healthy
docker-compose exec postgres pg_isready -U purpleteam

# Check connection string
docker-compose exec api env | grep PURPLE_DB
```

### API returns 401 Unauthorized
- Verify `PURPLE_API_KEYS` is set in `.env`
- Check that you're sending the correct header
- View API logs: `docker-compose logs api`

## Production Deployment

For production use:

1. **Use strong passwords:**
   ```bash
   # Generate secure password
   openssl rand -base64 32
   ```

2. **Enable HTTPS:**
   - Add nginx reverse proxy with SSL certificates
   - Use Let's Encrypt for free SSL certificates

3. **Configure resource limits** in `docker-compose.yml`:
   ```yaml
   services:
     api:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 2G
   ```

4. **Regular backups:**
   - Schedule automated database backups
   - Store backups off-site

5. **Monitor logs:**
   - Use log aggregation (ELK, Splunk, etc.)
   - Set up alerts for errors

## Development

### Build specific stage
```bash
# Build API server only
docker build --target api -t purpleteam-api .

# Build worker only
docker build --target worker -t purpleteam-worker .

# Build scanner
docker build --target scanner -t purpleteam-scanner .
```

### Run scanner manually
```bash
docker run -it --rm \
  -v $(pwd)/data:/app/data \
  purpleteam-scanner \
  python /app/bin/purple-launcher --non-interactive standard
```

### Access container shell
```bash
docker-compose exec api /bin/bash
docker-compose exec scheduler /bin/bash
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | `changeme` |
| `POSTGRES_USER` | PostgreSQL username | `purpleteam` |
| `POSTGRES_DB` | PostgreSQL database name | `purpleteam` |
| `PURPLE_DB_BACKEND` | Database backend (`sqlite` or `postgres`) | `postgres` |
| `PURPLE_DB_URL` | PostgreSQL connection URL | Auto-generated |
| `NVD_API_KEY` | NVD API key for higher rate limits | None |
| `PURPLE_API_KEYS` | Comma-separated list of API keys | None |

## Support

For issues or questions:
- Check logs: `docker-compose logs -f`
- Review this README
- Check main project documentation
