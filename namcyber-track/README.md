# NamCyber Track
Public form: `/`   Admin dashboard: `/admin`

## Run
    pip install -r requirements.txt
    ADMIN_PASSWORD='choose-a-long-passphrase' python server.py        # http://127.0.0.1:5000

## Production
    ADMIN_PASSWORD=... SECRET_KEY=$(openssl rand -hex 32) HTTPS=1 DB_PATH=/var/lib/namcyber-track/reports.db \
    ALERT_WEBHOOK=https://hooks.slack.com/... gunicorn -w 2 -b 127.0.0.1:8000 server:app
Put it behind nginx/Caddy with HTTPS. Back up reports.db regularly and apply a retention policy.

## Env vars
ADMIN_PASSWORD, SECRET_KEY, HTTPS=1, DB_PATH, ALERT_WEBHOOK (Critical alerts), HOST, PORT
