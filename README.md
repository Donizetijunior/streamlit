# Dashboard AWS Inspector

Este é um dashboard interativo para visualização de vulnerabilidades do AWS Inspector.

## Funcionalidades

- Visualização de vulnerabilidades por instância
- Análise de severidade
- Filtros avançados
- Exportação de dados
- Gerenciamento de usuários

## Instalação

1. Clone o repositório
2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## Executando Localmente

```bash
streamlit run app.py
```

## Deploy

Este projeto está configurado para deploy no Streamlit Cloud.

## 🧩 Requisitos

- Python 3.8+
- Streamlit
- Pandas

## 🚀 Executar Localmente

```bash
git clone https://seurepo.com/inspector_dashboard.git
cd inspector_dashboard
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install -r requirements.txt
streamlit run app.py
