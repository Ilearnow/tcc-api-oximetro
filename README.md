# TCC - Sistema de monitoramento de oxímetro com API segura

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green.svg)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-✓-blue.svg)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/Security-mTLS%2CTLS%201.3-red.svg)](https://owasp.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Sistema completo para monitoramento remoto de dados de oxímetro com foco em segurança, desenvolvido como parte de um trabalho de conclusão de curso (TCC) sobre análise de riscos e ameaças em APIs médicas.

---

## Índice

* Visão geral
* Arquitetura
* Principais funcionalidades
* Tecnologias utilizadas
* Instalação e execução
* Comandos úteis
* Estrutura do projeto
* Endpoints da API
* Configuração de segurança
* Testes de segurança
* Ameaças mitigadas
* Licença

---

## Visão geral

Este projeto implementa uma API REST segura para coleta, processamento e consulta de dados de oxímetros, com foco em segurança da informação. O sistema foi desenvolvido seguindo a metodologia **security by design**, onde cada componente foi projetado considerando ameaças identificadas por meio da modelagem STRIDE.

### Objetivos principais

* Coleta segura de dados médicos via dispositivos IoT
* Autenticação forte com mutual TLS (mTLS)
* Validação rigorosa de dados médicos
* Sistema de auditoria com integridade garantida
* Controle de acesso granular para prevenção de BOLA
* Criptografia em múltiplas camadas

---

## Arquitetura

```
┌─────────────────┐     ┌──────────────┐     ┌────────────────┐
│ Emulador        │────▶│ Caddy        │────▶│ FastAPI        │
│ de oxímetro     │     │ Proxy        │     │ (Python)       │
│ (mTLS)          │     │ (mTLS/TLS)   │     │                │
└─────────────────┘     └──────────────┘     └────────┬───────┘
                                                       │
                                                  ┌────▼────┐
                                                  │PostgreSQL│
                                                  │15        │
                                                  └──────────┘
```

### Componentes principais

1. API FastAPI responsável pelo backend e validação de dados.
2. Caddy server atuando como proxy reverso com suporte a TLS e mTLS.
3. PostgreSQL com schemas segregados para dados e auditoria.
4. Emulador de oxímetro para simulação de envio seguro de dados.
5. Suíte de testes automatizados com foco em segurança.

---

## Principais funcionalidades

### Para dispositivos médicos

* Envio seguro de leituras via mTLS
* Autenticação por certificados X.509
* Assinatura digital dos dados enviados
* Validação em tempo real das medições

### Para profissionais de saúde

* Autenticação baseada em JWT
* Consulta de leituras por paciente
* Visualização de histórico clínico
* Gestão de pacientes associados

### Para administradores

* Monitoramento e consulta de auditoria
* Verificação de integridade dos logs
* Registro de novos dispositivos
* Controle administrativo de acesso

---

## Tecnologias utilizadas

### Backend

* Python 3.11
* FastAPI
* Pydantic
* SQLAlchemy
* JWT
* bcrypt

### Banco de dados

* PostgreSQL 15
* Schemas segregados (`core` e `audit`)
* Índices otimizados para consultas

### Segurança e infraestrutura

* Caddy server
* TLS 1.3
* Mutual TLS (mTLS)
* Docker e Docker Compose
* Criptografia AES-256

### Testes e qualidade

* Pytest
* Requests
* OpenSSL

---

## Instalação e execução

### Pré-requisitos

* Docker 20.10 ou superior
* Docker Compose
* Python 3.11 ou superior
* Git

### Instalação rápida com Docker

```bash
git clone https://github.com/seu-usuario/tcc-api-oximetro.git
cd tcc-api-oximetro

cp .env.example .env
docker-compose up --build -d
```

A aplicação ficará disponível nos seguintes endereços:

* API HTTP: [http://localhost:8000](http://localhost:8000)
* API HTTPS sem mTLS: [https://localhost:9444](https://localhost:9444)
* API HTTPS com mTLS: [https://localhost:9443](https://localhost:9443)

---

## Comandos úteis

Esta seção reúne comandos frequentemente utilizados para execução, manutenção, depuração e testes do sistema.

### Gerenciamento de containers Docker

```bash
docker-compose up -d
docker-compose down
docker-compose down -v
docker-compose up --build -d
docker-compose ps
```

### Visualização de logs

```bash
docker-compose logs -f
docker-compose logs -f api
docker-compose logs -f caddy
docker-compose logs -f postgres
```

### Acesso aos containers

```bash
docker-compose exec api bash
docker-compose exec postgres psql -U tcc_user -d tcc_health_db
```

### Execução de comandos internos na API

```bash
docker-compose exec api python -c "from app.auth import hash_password; print(hash_password('teste'))"
```

### Monitoramento e limpeza

```bash
docker-compose stats
docker system prune -f
```

### Testes automatizados

```bash
python testar_sistema.py
python testes_seguranca.py
```

### Testes manuais

```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=dr.jose&password=secret1234"

curl -k https://localhost:9444/health
curl -k --cert certs/client.pem https://localhost:9443/mtls-info
```

### Reinicialização completa do ambiente

```bash
docker-compose down -v
rm -rf certs/*
docker-compose up --build -d
```

---

## Estrutura do projeto

```
tcc-api-oximetro/
├── app/
├── certs/
├── scripts/
├── tests/
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.emulator
├── Caddyfile
├── requirements.txt
├── init.sql
└── README.md
```

---

## Endpoints da API

### Autenticação e saúde

* POST /login
* GET /health
* GET /security-info
* GET /mtls-info
* GET /compliance/policy

### Leituras e pacientes

* POST /readings
* GET /patients
* GET /readings/{patient_code}

### Auditoria

* GET /logs
* GET /audit/verify/{log_id}
* GET /audit/verify-all

---

## Configuração de segurança

O sistema utiliza TLS 1.3, mutual TLS para dispositivos IoT, JWT para usuários humanos, RBAC para controle de acesso e auditoria com hash criptográfico para prevenção de repúdio.

---

## Testes de segurança

O projeto possui testes automatizados que validam autenticação, autorização, validação de entrada, proteção contra injeção, integridade de logs e obrigatoriedade de mTLS.

---

## Ameaças mitigadas

O sistema mitiga as principais ameaças do OWASP API Security Top 10 (2023), além de riscos específicos do domínio médico, como sniffing, spoofing de dispositivos, BOLA e adulteração de registros clínicos.

---

## Licença

Este projeto é desenvolvido para fins acadêmicos como trabalho de conclusão de curso.

Desenvolvido para o TCC em segurança da informação.
