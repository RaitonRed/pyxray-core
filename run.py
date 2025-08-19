import logging
from pyxray.core import PyXrayCore

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    proxy = PyXrayCore()
    try:
        # مثال لینک VMess (base64 encoded)
        vmess_link = (
            "vmess://eyJhZGQiOiJkYXNoYm9hcmQucG9ydGV4bGFicy54eXoiLCJhaWQiOiIwIiwiYWxwbiI6IiIsImZwIjoiIiwiaG9zdCI6InNwZWVkdGVzdC5uZXQiLCJpZCI6ImE5MDZhMjE4LWMzMGMtNDczZC04YjFjLWRlZDA0OTY1NDkxNyIsIm5ldCI6InRjcCIsInBhdGgiOiIvIiwicG9ydCI6IjIwODMwIiwicHMiOiJb8J+HrvCfh7dddC5tZS9Db25maWdzSHViIiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJodHRwIiwidiI6IjIifQ=="
        )
        
        proxy.config(
            link=vmess_link,
            tun=True,
            dns_mode="doh"
        )
        proxy.run_proxy()
    except KeyboardInterrupt:
        proxy.stop()