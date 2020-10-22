#!/bin/bash

# https://tools.ietf.org/html/rfc7515#appendix-C
function create_base64_url {
    local base64text="$1"
    echo -n "${base64text}" | sed -E s%=+$%% | sed s%\+%-%g | sed -E s%/%_%g 
}

function hmac_sha256 {
    local base64Key="$1"
    local signature_input="$2"
    local hexkey base64hmac

    hexkey="$( echo -n "${base64Key}" | base64 -d | od -t x1 -An | tr -d '\n ' )"
    base64hmac="$( echo -n "${signature_input}" | openssl dgst -sha256 -mac hmac -macopt "hexkey:${hexkey}" -binary | base64 --wrap=0 )"

    create_base64_url "${base64hmac}"
}

function json_to_base64 {
    local jsonText="$1"
    local encoded
    
    encoded="$( echo -n "${jsonText}" | base64 --wrap=0 )"
    create_base64_url "${encoded}"
}

function sign_json {
    local base64Key="$1"
    local jsonPayloadText="$2"
    local algorithm header_json header payload signature_input sig

    # https://tools.ietf.org/html/rfc7515
    # header="$( json_to_base64 '{"alg":"HS256","typ":"JWT"}' )"

    algorithm="HS256"
    header_json="$( echo "{}"                 | \
        jq --arg x "${algorithm}" '.alg=($x)' | \
        jq --arg x "JWT"          '.typ=($x)' | \
        iconv --from-code=ascii --to-code=utf-8 )"

    header="$(  json_to_base64 "${header_json}" )"
    payload="$( json_to_base64 "${jsonPayloadText}" )"
    signature_input="$( echo -n "${header}.${payload}" | iconv --to-code=ascii )"
    sig="$( hmac_sha256 "${base64Key}" "${signature_input}" )"

    echo "${header}.${payload}.${sig}" | iconv --to-code=ascii
}

function get_current_utc_time {
    date --utc +"%Y-%m-%dT%H:%M:%SZ"
}

function generate_request {
    local base64Key="$1"
    local tenantID="$2"
    local subscriptionID="$3"
    local timestamp="$4"
    local json

    json="$( echo "{}"                                        | \
        jq --arg x "${tenantID}"       '.tenantId=($x)'       | \
        jq --arg x "${subscriptionID}" '.subscriptionId=($x)' | \
        jq --arg x "${timestamp}"      '.timeStamp=($x)'      | \
        jq --arg x '[ "subj" ]'        '.claims=($x | fromjson)' | \
        jq -c -M | iconv --from-code=ascii --to-code=utf-8 )"
    
    sign_json "${base64Key}" "${json}"
}

base64Key="pDzCAKG9KSaCWY2kLaqf0UWJ89i/gy/6IGvndSWe4eo="
tenantID="chgeuerfte.onmicrosoft.com"
subscriptionID="fb7fdc26-b0e5-45b6-8119-7bc48bc12e4e"

generate_request "${base64Key}" "${tenantID}" "${subscriptionID}" "$( get_current_utc_time )"
