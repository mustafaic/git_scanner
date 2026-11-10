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

## teams_encryption_key

Microsoft Teams webhook bildirimleri (`/settings` sayfası, `core/notifications.py`,
docs/THREAT_MODEL.md madde 9: "webhook URL'si DB'de şifreli saklanmalı") için
Fernet anahtarı. Webhook URL'sinin kendisi admin panelden girilir ve bu
anahtarla şifrelenip DB'ye yazılır -- `backup_encryption_key`'den AYRI bir
anahtardır (farklı veri, farklı anahtar). Üretmek için:

```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > deploy/secrets/teams_encryption_key
```

Bu dosya yoksa (veya `TEAMS_ENCRYPTION_KEY_PATH` boşsa) `/settings` sayfası
webhook URL'si kaydetmeyi reddeder (açık hata, sessizce şifresiz saklamaz).
`docker-compose.yml` bu dosyayı hem `app` hem `orchestrator` servislerine
`/run/secrets/teams_encryption_key` olarak salt-okunur mount eder -- ikisi
de AYNI anahtara ihtiyaç duyar (app şifreler, orchestrator çözüp gönderir).
Anahtar değişirse önceden kaydedilmiş webhook URL'si çözülemez hale gelir;
admin `/settings` sayfasından URL'yi yeniden girmelidir.

## repo_token_encryption_key

Panelden GitHub token ile repo ekleme (hibrit model, `/repositories` sayfası
"+ Proje Ekle", `app/routes_repos.py`, `core.models.RepoOnboardingRequest`/
`RepoCredential`) için Fernet anahtarı -- yukarıdaki iki anahtarla AYNI
mekanizma (`core/backup_crypto.py`), AYRI bir anahtar (admin'in panelden
girdiği GitHub PAT'leri, webhook URL'sinden veya DB yedeğinden farklı bir
veri sınıfı). Üretmek için:

```
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > deploy/secrets/repo_token_encryption_key
```

Bu dosya yoksa (veya `REPO_TOKEN_ENCRYPTION_KEY_PATH` boşsa) "+ Proje Ekle"
formu token kaydetmeyi reddeder (açık hata, sessizce şifresiz saklamaz).
`docker-compose.yml` bu dosyayı hem `app` hem `orchestrator` servislerine
`/run/secrets/repo_token_encryption_key` olarak salt-okunur mount eder --
app şifreler (admin formdan girince), orchestrator çözüp GitHub'a karşı
kullanır. Anahtar değişirse önceden eklenmiş manuel repoların token'ı
çözülemez hale gelir -- repo taranamaz duruma düşer, admin token'ı
`/repositories` sayfasından yeniden girmelidir.
