# certbot-dns-zone

Zone (https://zone.ee) DNS Authenticator plugin for Certbot

## Usage

Generate an API token in Zone and create `zone-credentials.ini` containing

```ini
dns_zone_username = YOUR_ZONE_ID_USERNAME
dns_zone_api_token = YOUR_ZONE_API_TOKEN
```

Example:

```shell
certbot certonly --authenticator dns-zone --dns-zone-credentials ~/zone-credentials.ini --dns-zone-propagation-seconds 30 -d example.com
```

Using the default propagation of 10 seconds was not successful in my attempts so I recommend using 30 seconds as shown above.
