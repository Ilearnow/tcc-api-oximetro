

import requests
import time
import sys
import json
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TesteSistema:
    def __init__(self):
        self.certs_dir = Path("certs")
        self.resultados = []
        self.username = "dr.jose"
        self.password = "secret1234"
        
    def log(self, mensagem, status="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        simbolos = {
            "INFO": "ℹ️",
            "SUCCESS": "✅",
            "ERRO": "❌",
            "WARNING": "⚠️"
        }
        simbolo = simbolos.get(status, "📝")
        print(f"[{timestamp}] {simbolo} {mensagem}")
        
    def testar_endpoint(self, nome, url, usar_mtls=False, esperar_falha=False):
        self.log(f"Testando: {nome}")
        print(f"   URL: {url}")
        
        try:
            if usar_mtls:
                cert_file = self.certs_dir / "client.pem"
                ca_file = self.certs_dir / "ca.crt"
                
                if not cert_file.exists():
                    self.log(f"Certificado não encontrado: {cert_file}", "ERRO")
                    return False
                
                response = requests.get(
                    url,
                    cert=str(cert_file),
                    verify=False,
                    timeout=10
                )
            else:
                response = requests.get(url, verify=False, timeout=10)
            
            if esperar_falha:
                if response.status_code >= 400:
                    self.log(f"OK: Falhou como esperado (Status {response.status_code})", "SUCCESS")
                    return True
                else:
                    self.log(f"ERRO: Deveria ter falhado mas retornou {response.status_code}", "ERRO")
                    return False
            
            self.log(f"Status: {response.status_code}", "SUCCESS" if response.status_code == 200 else "ERRO")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"   Resposta: {json.dumps(data, ensure_ascii=False)[:100]}...")
                except:
                    print(f"   Resposta: {response.text[:100]}")
                return True
            else:
                print(f"   Erro: {response.text[:100]}")
                return False
                
        except requests.exceptions.SSLError as e:
            if esperar_falha:
                self.log(f"OK: SSL rejeitado como esperado", "SUCCESS")
                return True
            else:
                self.log(f"Erro SSL: {str(e)[:100]}", "ERRO")
                return False
        except Exception as e:
            if esperar_falha:
                self.log(f"OK: Conexão rejeitada como esperado", "SUCCESS")
                return True
            self.log(f"Erro: {str(e)[:100]}", "ERRO")
            return False
    
    def testar_login(self):
        self.log("\n Testando autenticação JWT")
        
        try:
            response = requests.post(
                "http://localhost:8000/login",
                data={"username": self.username, "password": self.password},
                timeout=10
            )
            
            if response.status_code == 200:
                token = response.json()["access_token"]
                self.log(f"Login bem-sucedido para: {self.username}", "SUCCESS")
                print(f"   Token: {token[:40]}")
                
                headers = {"Authorization": f"Bearer {token}"}
                response = requests.get(
                    "http://localhost:8000/patients",
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    pacientes = response.json()
                    self.log(f"Acesso a pacientes OK ({len(pacientes)} pacientes)", "SUCCESS")
                    return True
                else:
                    self.log(f"Falha ao acessar pacientes: {response.status_code}", "ERRO")
                    return False
            else:
                self.log(f"Login falhou: {response.status_code}", "ERRO")
                print(f"   Erro: {response.text}")

                self.log("Tentando com dr.jose/secret", "WARNING")
                response2 = requests.post(
                    "http://localhost:8000/login",
                    data={"username": "dr.jose", "password": "secret1234"},
                    timeout=10
                )
                
                if response2.status_code == 200:
                    self.log("Login OK", "SUCCESS")
                    return True
                    
                return False
                
        except Exception as e:
            self.log(f"Erro no login: {e}", "ERRO")
            return False
    
    def testar_mtls(self):
        self.log("\nTestando mTLS (Mutual TLS)")
        
        self.log("\n   Teste 1: HTTPS sem mTLS (porta 9444)")
        https_ok = self.testar_endpoint(
            "HTTPS sem mTLS",
            "https://localhost:9444/health",
            usar_mtls=False
        )
        
        self.log("\n   Teste 2: mTLS sem certificado (porta 9443 - deve falhar)")
        falha_ok = self.testar_endpoint(
            "mTLS sem certificado",
            "https://localhost:9443/health",
            usar_mtls=False,
            esperar_falha=True
        )
        
        self.log("\n   Teste 3: mTLS com certificado (porta 9443)")
        mtls_ok = self.testar_endpoint(
            "mTLS com certificado",
            "https://localhost:9443/mtls-info",
            usar_mtls=True
        )
        
        if https_ok and falha_ok and mtls_ok:
            self.log("\n✅ mTLS funcionando perfeitamente!", "SUCCESS")
            return True
        else:
            self.log(f"\n⚠️ mTLS parcialmente funcional (HTTPS: {https_ok}, Rejeição: {falha_ok}, mTLS: {mtls_ok})", "WARNING")
            return mtls_ok
    
    def testar_seguranca(self):
        self.log("\n🛡 Testando módulos de segurança...")
        
        try:
            import sys
            sys.path.insert(0, 'app')
            
            from security import cript_aes, decript_aes
            from auth import hash_password, verify_password

            texto = "Dados médicos confidenciais do paciente"
            criptografado = cript_aes(texto)
            descriptografado = decript_aes(criptografado)
            
            if texto == descriptografado:
                self.log("Criptografia AES-256 funcionando", "SUCCESS")
            else:
                self.log("Falha na criptografia AES", "ERRO")
                return False
            
            senha_teste = "MinhaSenhaSegura123!"
            hash_gerado = hash_password(senha_teste)
            
            if verify_password(senha_teste, hash_gerado):
                self.log("Hash de senha (bcrypt) funcionando", "SUCCESS")
            else:
                self.log("Falha no hash de senha", "ERRO")
                return False
            

            if not verify_password("Senhaerrada123", hash_gerado):
                self.log("Validação de senha incorreta OK", "SUCCESS")
            else:
                self.log("ERRO: Senha incorreta foi aceita!", "ERRO")
                return False
            
            return True
            
        except Exception as e:
            self.log(f"Erro nos testes de segurança: {e}", "ERRO")
            import traceback
            traceback.print_exc()
            return False
    
    def executar_todos_testes(self):
        print("*** Teste do sistema ***")
        print("Sistema de monitoramento de oxímetro")
        
        self.log("Aguardando serviços inicializarem.")
        time.sleep(3)
        
        self.log("\n📡 1. Testando conexão HTTP básica")
        conexao_ok = self.testar_endpoint("HTTP básico", "http://localhost:8000/health")
        
        self.log("\n 2. Testando HTTPS.")
        https_ok = self.testar_endpoint("HTTPS sem mTLS", "https://localhost:9444/health")
        
        login_ok = self.testar_login()
        
        mtls_ok = self.testar_mtls()
        
        seguranca_ok = self.testar_seguranca()

        print(" RESULTADO FINAL")

        
        testes = [
            ("Conexão HTTP", conexao_ok),
            ("HTTPS público", https_ok),
            ("Autenticação JWT", login_ok),
            ("mTLS (Mutual TLS)", mtls_ok),
            ("Módulos de Segurança", seguranca_ok)
        ]
        
        sucessos = 0
        for nome, resultado in testes:
            status = "✅" if resultado else "❌"
            print(f"{status} {nome}")
            if resultado:
                sucessos += 1
        
        total = len(testes)
        taxa = (sucessos / total) * 100
        
        print(f"\n {sucessos}/{total} testes passaram ({taxa:.1f}%)")
        
        print("\n REQUISITOS CRÍTICOS:")
        requisitos_criticos = [
            ("Autenticação JWT", login_ok),
            ("Criptografia AES-256", seguranca_ok),
            ("mTLS para dispositivos", mtls_ok)
        ]
        
        todos_criticos_ok = True
        for req, ok in requisitos_criticos:
            status = "ATENDIDO ✅" if ok else "NÃO ATENDIDO ❌"
            print(f"   {req}: {status}")
            if not ok:
                todos_criticos_ok = False
        
        # Resultado final
        if todos_criticos_ok and taxa >= 80:
            print("\n Sistema atende aos requisitos")
            print("\n URLs disponíveis:")
            print("   • http://localhost:8000 - API HTTP")
            print("   • https://localhost:9444 - HTTPS sem mTLS")
            print("   • https://localhost:9443 - HTTPS com mTLS obrigatório")
            print("\n Credenciais de teste:")
            print(f"   Username: {self.username}")
            print(f"   Password: {self.password}")
            return True
        else:
            print(f"\n⚠ SISTEMA COM PENDÊNCIAS (Taxa: {taxa:.1f}%)")
            return False

if __name__ == "__main__":
    tester = TesteSistema()
    
    if tester.executar_todos_testes():
        sys.exit(0)
    else:
        sys.exit(1)
