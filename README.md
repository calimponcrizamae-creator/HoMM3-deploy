# HoMM3-deploy

Heroes of Might and Magic III - online backend server.

## Local setup

This repo includes a Node.js backend and Docker Compose configuration for PostgreSQL + Redis.

### 1. Build and run with Docker Compose

```bash
docker compose up --build
```

The server will be available at `http://localhost:3000`.

### 2. Direct Node.js startup

If you want to run the app directly, install dependencies and start the server:

```bash
npm install
npm start
```

### 3. Environment variables

Copy `.env.example` to `.env` to override defaults.

### 4. Services

- `postgres` on port `5432`
- `redis` on port `6379`
- `Node` backend on port `3000`

### 5. Notes

- The server uses `pg` for PostgreSQL and `redis` for Redis connectivity.
- Redis connection errors are logged without crashing the server.
