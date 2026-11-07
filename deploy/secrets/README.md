# deploy/secrets/

Bu dizin **git'e girmez** (bkz. kök `.gitignore`: `deploy/secrets/*`).

GitHub App private key'ini buraya `github_app_private_key.pem` adıyla
koyun (indirdiğiniz `.pem` dosyasını kopyalayın), dosya izinlerini
kısıtlayın, ve `.env`'de `GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github_app_private_key.pem`
olarak ayarlayın (docker-compose.yml bu dizini `/run/secrets` olarak mount eder).

Gerçek key dosyası yoksa orchestrator servis **skeleton modda** çalışır
(discovery/sync devre dışı, healthcheck/job-queue/watchdog normal çalışır) —
bkz. `orchestrator/main.py`.
