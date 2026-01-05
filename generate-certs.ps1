Write-Host "Gerando certificados via Docker" -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path "certs" | Out-Null

docker run --rm -v "${PWD}/certs:/certs" alpine:latest sh -c @"
apk add --no-cache openssl

cd /certs

openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj '/C=BR/ST=RJ/O=TCC/CN=Root CA'

echo 'gerando certificado do servidor com SANs'
cat > server.cnf <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=BR
ST=RJ
O=TCC
CN=localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = caddy
DNS.3 = api
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl req -newkey rsa:4096 -keyout server.key -out server.csr -nodes -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile server.cnf

echo 'gerando certificado do cliente'
openssl req -newkey rsa:4096 -keyout client.key -out client.csr -nodes -subj '/C=BR/ST=RJ/O=TCC/CN=client'
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt -days 365

cat client.crt client.key > client.pem

openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt -passout pass:

chmod 644 *.crt *.pem *.p12
chmod 600 *.key

echo 'certificados gerados!'
ls -lh
"@

Write-Host "`n certificados atualizados!" -ForegroundColor Green
Get-ChildItem -Path "certs" -File | Format-Table Name, @{Label="Size (KB)"; Expression={[math]::Round($_.Length/1KB, 2)}}
