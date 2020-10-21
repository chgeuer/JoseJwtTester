
# Demo for JOSE JSON object signing

```bash
#!/bin/bash

# https://gist.github.com/indrayam/dd47bf6eef849a57c07016c0036f5207

function base64_for_token {
    local base64Content="$1"
    # echo "$( echo -n "${base64Content}" | sed -E s/\+/-/ | sed -E s/\//_/ | sed -E s/=+$// )"

    echo "$( echo -n "${base64Content}" | sed s/\+/-/g | sed -E sQ/Q_Qg | sed -E s/=+$//)"
}

function hmac_sha256 {
    local base64Key="$1"
    local plaintext="$2"

    local hexkey="$( echo -n "${base64Key}" | base64 -d | od -t x1 -An | tr -d '\n ' )"
    local base64hmac="$( echo -n "${plaintext}" | openssl dgst -sha256 -mac hmac -macopt "hexkey:${hexkey}" -binary | base64 --wrap=0 )"

    echo "$( base64_for_token "${base64hmac}" )"
}

function json_to_base64 {
    local jsonText="$1"
    local encoded="$( echo -n "${jsonText}" | base64 --wrap=0 )"
    echo "$( base64_for_token "${encoded}" )"
}

function sign_json {
    local base64Key="$1"
    local jsonPayloadText="$2"

    local header="$( json_to_base64 '{"alg":"HS256","typ":"JWT"}' )"
    local payloadBase64="$( json_to_base64 "${jsonPayloadText}" )"
    local sig="$( hmac_sha256 "${base64Key}" "${header}.${payloadBase64}" )"

    echo "${header}.${payloadBase64}.${sig}"
}

base64Key="pDzCAKG9KSaCWY2kLaqf0UWJ89i/gy/6IGvndSWe4eo="

tenantID="chgeuerfte.onmicrosoft.com"
subscriptionID="fb7fdc26-b0e5-45b6-8119-7bc48bc12e4e"
timestamp="$( date --utc +"%Y-%m-%dT%H:%M:%SZ" )"
#timestamp="2020-10-21T11:36:01+00:00"

echo "$( sign_json "${base64Key}" "{\"tenantId\":\"${tenantID}\",\"subscriptionId\":\"${subscriptionID}\",\"timeStamp\":\"${timestamp}\"}" )"
```
