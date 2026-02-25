# Backend Quickstart

Stack implementado:
- Bun + Hono API
- bun:sqlite para cola de trabajos y hallazgos
- Worker polling (`bun run worker.ts`)
- Ejecucion de herramientas por Docker (`docker run --rm ...`)

## Ejecutar
1. `bun install`
2. `bun run api`
3. `bun run worker`
4. Abrir `http://localhost:3000/` (frontend básico)

## Endpoints
- `GET /health`
- `GET /system/status`
- `GET /system/preflight?deep=0|1`
- `POST /uploads` (multipart: `file`, opcional `kind`)
- `POST /jobs`
- `GET /jobs?limit=25`
- `GET /jobs/:id`
- `GET /jobs/:id/logs?after=0`
- `GET /jobs/:id/findings`
- `GET /jobs/:id/findings/:findingId`
- `POST /jobs/:id/cancel`
- `DELETE /jobs/:id`

## Ejemplos

Crear upload:
```bash
curl -X POST http://localhost:3000/uploads -F "kind=archive" -F "file=@./repo.zip"
```

Crear job de git:
```bash
curl -X POST http://localhost:3000/jobs \
  -H "Content-Type: application/json" \
  -d '{"inputType":"git_url","payload":{"repoUrl":"https://github.com/owner/repo"}}'
```

Crear job de archivo subido:
```bash
curl -X POST http://localhost:3000/jobs \
  -H "Content-Type: application/json" \
  -d '{"inputType":"archive_upload","payload":{"uploadId":"<UPLOAD_ID>"}}'
```

Crear job de imagen Docker:
```bash
curl -X POST http://localhost:3000/jobs \
  -H "Content-Type: application/json" \
  -d '{"inputType":"docker_image","payload":{"image":"nginx:latest","saveTar":true}}'
```

Gate de despliegue:
```bash
curl -X POST http://localhost:3000/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "inputType":"git_url",
    "payload":{"repoUrl":"https://github.com/owner/repo","manifestUploadId":"<UPLOAD_ID>"},
    "policy":{"blockOn":{"critical":0,"high":0},"deployGate":{"enabled":true,"targetUrl":"http://app.example.com"}}
  }'
```
