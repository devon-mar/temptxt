# temptxt

## Name

*temptxt* - serves TXT records for validation purposes (eg. ACME DNS-01 challenge) updated through a HTTP api.

## Description

The *temptxt* plugin is useful for delegating the configuration of TXT records for purposes such as certificate validation (eg. ACME DNS-01).

Users can update the content of the TXT records through a HTTP API. Authentication to the API is handled by a HTTP header passed
from the upstream reverse proxy.

## Syntax
```
temptxt [PREFIX] [SUFFIX] {
    [txt FQDN REGEXP1 REGEXP2 ...]
    [txt_alias ACTUAL_FQDN UPDATE_FQDN REGEXP1 REGEXP2 ...]

    [auth_header X-Forwarded-User]
    [clean_interval DURATION]
    [max_age DURATION]
    [listen ADDRESS]
}
```
* `PREFIX` - Prefix to add to FQDNs. This only affects DNS queries. Updates through the API need to use the FQDN without the prefix (txt_alias doesn't used prefix).
* `SUFFIX` - Suffix to add to FQDNs. This only affects DNS queries. Updates through the API need to use the FQDN without the suffix (txt_alias doesn't used suffix).
* `txt` - FQDN to serve txt records for. If one of the regexps matches the username, the API request will be allowed. Regexps are automatically anchored with `^` and `$`.
* `txt_alias` - Useful in use cases like example 2. UPDATE_FQDN is the FQDN that is used when calling the API, but the TXT record for ACTUAL_FQDN will be the one that is actually updated.
* `auth_header` - The header that contains the username for API authentication.  Make sure that this a user cannot set the contents of the header. Default: `X-Forwarded-User`
* `clean_interval` - The interval that records will be periodically cleared. Set to 0 to disable cleaning. Default: `0`.
* `max_age` - If the time since the record has last been updated is greater than the given duration, the contents will be cleared. Default: `15m0s`
* `listen` - The address to listen on. Default: `:8080`

## Example 1 - ACME DNS-01

Use *temptxt* for acme DNS-01 validation for `test1.example.com` and `test2.example.com`. CoreDNS is authoritative for `example.com`.

### Configuration
1. CoreDNS configuration
   ```
   temptxt _acme-challenge. {
       txt test1.example.com user1
       txt test2.example.com user[0-2] user4
   }
   ```
   Also equivalent:
   ```
   temptxt {
       txt _acme-challenge.test1.example.com user1
       txt _acme-challenge.test2.example.com user[0-2] user4
   }
   ```

2. Configure the ACME client to call the `temptxt` API.

### Outcome

* The content of `_acme-challenge.test1.example.com` can be updated by `user1`.

* The content of `_acme-challenge.test2.example.com` can be updated by `user1`, `user2`, and `user4`.

* Queries for other `_acme-challenge.*.example.com` records will fallthrough.

* If the content of the txt record is `""`, `NXDOMAIN` will be returned.

## Example 2 - ACME DNS Alias

* The is similar to [acme-dns](https://github.com/joohoi/acme-dns). It allows temptxt to be used for validation when CoreDNS is not the authoritative server for a given zone using CNAMEs.

### Configuration
1. Create NS records for `acme-dns.example.com` pointing to this server.

2. Create a CNAME from `_acme-challenge.www.example.com` to `www.acme-dns.example.com` on the DNS server for `example.com`

3. Configure CoreDNS
   ```
   temptxt {
       txt_alias www.acme-dns.example.com www.example.com user1
   }
   ```

4. Configure the ACME client to call the `temptxt` API.

### Results
1. The ACME client will update the TXT record for `www.acme-dns.example.com` using the API.

2. Since there is a CNAME from `_acme-challenge.www.example.com` the ACME server will query *temptxt* for the validation string.

## Example certbot hooks

Update using basic auth
```
curl -X POST \
    -d "fqdn=www.example.com&content=$CERTBOT_TOKEN" \
    -u username:password \
    https://acme-dns.example.com/update

```

Clear the record using certificate auth
```
curl -X POST \
    -d "fqdn=www.example.com&content=" \
    --cert ./cert.crt \
    --key ./cert.key \
    https://acme-dns.example.com/update
```
