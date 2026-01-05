import subprocess
import os
from pathlib import Path

def main():
    print("GERANDO CERTIFICADOS TCC ")
    
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    
    # 1. CA Root
    print("\n1. Gerando CA Root...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(certs_dir / "ca.key"),
        "-out", str(certs_dir / "ca.crt"),
        "-days", "3650",
        "-nodes",
        "-subj", "/C=BR/ST=SP/L=SaoPaulo/O=TCC Hospital/CN=TCC Root CA"
    ], check=True)
    
    print("\n2. Gerando certificado do servidor (com SAN)...")
    
    san_config = certs_dir / "server.ext"
    with open(san_config, "w") as f:
        f.write("""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = api
DNS.3 = caddy
IP.1 = 127.0.0.1
""")
    
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048",
        "-keyout", str(certs_dir / "server.key"),
        "-out", str(certs_dir / "server.csr"),
        "-nodes",
        "-subj", "/C=BR/ST=SP/L=SaoPaulo/O=TCC Hospital/CN=localhost"
    ], check=True)
    
    subprocess.run([
        "openssl", "x509", "-req",
        "-in", str(certs_dir / "server.csr"),
        "-CA", str(certs_dir / "ca.crt"),
        "-CAkey", str(certs_dir / "ca.key"),
        "-CAcreateserial",
        "-out", str(certs_dir / "server.crt"),
        "-days", "365",
        "-extfile", str(san_config)
    ], check=True)
    
    print("\n3. Gerando certificado do cliente (mTLS)")
    subprocess.run([
        "openssl", "req", "-newkey", "rsa:2048",
        "-keyout", str(certs_dir / "client.key"),
        "-out", str(certs_dir / "client.csr"),
        "-nodes",
        "-subj", "/C=BR/ST=SP/L=SaoPaulo/O=TCC Hospital/CN=oximeter-client"
    ], check=True)
    
    subprocess.run([
        "openssl", "x509", "-req",
        "-in", str(certs_dir / "client.csr"),
        "-CA", str(certs_dir / "ca.crt"),
        "-CAkey", str(certs_dir / "ca.key"),
        "-out", str(certs_dir / "client.crt"),
        "-days", "365"
    ], check=True)
    
    print("\n4. Criando arquivos PEM")
    
    with open(certs_dir / "server.pem", "wb") as f:
        f.write(open(certs_dir / "server.crt", "rb").read())
        f.write(open(certs_dir / "server.key", "rb").read())
    
    # client.pem (para testes curl)
    with open(certs_dir / "client.pem", "wb") as f:
        f.write(open(certs_dir / "client.crt", "rb").read())
        f.write(open(certs_dir / "client.key", "rb").read())
    
    print("\nCERTIFICADOS GERADOS:")
    print("="*30)
    for file in certs_dir.glob("*"):
        if file.is_file():
            print(f"✓ {file.name}")
    
    print("\n Para testar:")
    print("  curl -k --cert certs/client.pem https://localhost:9443/mtls-info")

if __name__ == "__main__":
    main()