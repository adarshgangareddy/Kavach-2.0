# Demo shop: Kavach runtime alerts

A small, safe Flask app with `kavach_telemetry` added, for showing the Monitoring page live.

1. In Kavach (http://localhost:8080), open **Monitoring**, register an app called `demo-shop`, copy the key.
2. From the repository root:

```bash
docker build -f demo/monitored-app/Dockerfile -t kavach-demo-shop .
docker run --rm -p 127.0.0.1:5000:5000 -e KAVACH_APP_KEY=kv_paste_your_key kavach-demo-shop
```

3. Send requests and watch the alerts appear. Use `127.0.0.1`, not `localhost`: on a Mac, AirPlay Receiver
   also listens on port 5000 and answers `localhost` with an empty 403.

```bash
curl "http://127.0.0.1:5000/products?q=lamp"                      # normal: no alert
curl "http://127.0.0.1:5000/products?q=1%27%20UNION%20SELECT%201"  # SQL injection pattern
curl "http://127.0.0.1:5000/files?name=../../etc/passwd"           # path traversal pattern
```

The app is safe either way (parameterised queries, `send_from_directory`), so attacks fail and
show up only as alerts. Add `-e KAVACH_BLOCK=true` to reject them with 403 as well.
