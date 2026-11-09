# deploy/secrets/

Bu dizin **git'e girmez** (bkz. kök `.gitignore`: `deploy/secrets/*`).

GitHub App private key'ini buraya `github_app_private_key.pem` adıyla
koyun (indirdiğiniz `.pem` dosyasını kopyalayın), dosya izinlerini
kısıtlayın, ve `.env`'de `GITHUB_APP_PRIVATE_KEY_PATH=/run/secrets/github_app_private_key.pem`
olarak ayarlayın (docker-compose.yml bu dizini `/run/secrets` olarak mount eder).

Gerçek key dosyası yoksa orchestrator servis **skeleton modda** çalışır
(discovery/sync devre dışı, healthcheck/job-queue/watchdog normal çalışır) —
bkz. `orchestrator/main.py`.

## backup_encryption_key

Şifreli yedekleme (`tools/backup.py`/`tools/restore.py`, master_prompt.md 5
"Yedekler şifreli") için Fernet anahtarı. Üretmek için:

```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > deploy/secrets/backup_encryption_key
```

**Bu anahtarı kaybederseniz geçmiş yedekleri BİR DAHA ASLA çözemezsiniz** --
anahtarı bu dizin dışında (ör. bir parola yöneticisinde) da saklayın.
`docker-compose.yml` bu dosyayı `backup`/`restore` servislerine
`/run/secrets/backup_encryption_key` olarak salt-okunur mount eder.
