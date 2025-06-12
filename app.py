import streamlit as st
import pandas as pd
import os
import re
from datetime import datetime
import json
import hashlib
import secrets
import shutil
from pathlib import Path

st.set_page_config(layout="wide")

# --- Arquivos externos ---
USERS_FILE = "usuarios.json"
LOG_FILE = "log_acessos.txt"
BACKUP_DIR = "backups"

# Criar diretório de backup se não existir
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

def criar_backup():
    """Cria um backup do arquivo de usuários"""
    if os.path.exists(USERS_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(BACKUP_DIR, f"usuarios_{timestamp}.json")
        shutil.copy2(USERS_FILE, backup_file)
        # Manter apenas os últimos 5 backups
        backups = sorted(Path(BACKUP_DIR).glob("usuarios_*.json"))
        if len(backups) > 5:
            for old_backup in backups[:-5]:
                old_backup.unlink()

def hash_senha(senha, salt=None):
    """Gera um hash seguro da senha"""
    if salt is None:
        salt = secrets.token_hex(16)
    hash_obj = hashlib.sha256()
    hash_obj.update((senha + salt).encode())
    return hash_obj.hexdigest(), salt

def validar_senha(senha):
    """Valida a força da senha"""
    if len(senha) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres"
    if not re.search(r"[A-Z]", senha):
        return False, "A senha deve conter pelo menos uma letra maiúscula"
    if not re.search(r"[a-z]", senha):
        return False, "A senha deve conter pelo menos uma letra minúscula"
    if not re.search(r"\d", senha):
        return False, "A senha deve conter pelo menos um número"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", senha):
        return False, "A senha deve conter pelo menos um caractere especial"
    return True, "Senha válida"

def carregar_usuarios():
    if not os.path.exists(USERS_FILE):
        return {"admin": {"senha": "123456", "perfil": "admin"}}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def salvar_usuarios(usuarios):
    criar_backup()  # Cria backup antes de salvar
    with open(USERS_FILE, 'w') as f:
        json.dump(usuarios, f, indent=4)

def registrar_acesso(usuario, sucesso=True):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCESSO" if sucesso else "FALHA"
    with open(LOG_FILE, "a") as f:
        f.write(f"[{now}] LOGIN: {usuario} - {status}\n")

def verificar_tentativas_login(usuario):
    """Verifica se o usuário excedeu o limite de tentativas de login"""
    if 'tentativas_login' not in st.session_state:
        st.session_state['tentativas_login'] = {}
    
    tentativas = st.session_state['tentativas_login'].get(usuario, 0)
    if tentativas >= 3:
        return False
    return True

def registrar_tentativa_login(usuario):
    """Registra uma tentativa de login"""
    if 'tentativas_login' not in st.session_state:
        st.session_state['tentativas_login'] = {}
    
    st.session_state['tentativas_login'][usuario] = st.session_state['tentativas_login'].get(usuario, 0) + 1

def resetar_tentativas_login(usuario):
    """Reseta as tentativas de login após sucesso"""
    if 'tentativas_login' in st.session_state:
        st.session_state['tentativas_login'][usuario] = 0

def migrar_usuarios():
    """Migra usuários existentes para o novo formato com senhas hasheadas"""
    usuarios_migrados = {}
    for usuario, dados in usuarios.items():
        if 'salt' not in dados:  # Se não tem salt, é senha em texto puro
            senha_hash, salt = hash_senha(dados['senha'])
            usuarios_migrados[usuario] = {
                "senha": senha_hash,
                "salt": salt,
                "perfil": dados['perfil'],
                "ultimo_acesso": dados.get("ultimo_acesso", "Nunca"),
                "data_criacao": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            usuarios_migrados[usuario] = dados
    return usuarios_migrados

# Carregar e migrar usuários se necessário
usuarios = carregar_usuarios()
if any('salt' not in dados for dados in usuarios.values()):
    usuarios = migrar_usuarios()
    salvar_usuarios(usuarios)
   

# --- Barra Lateral ---
with st.sidebar:
    st.title("Login")
    
    # Verifica se o usuário está autenticado
    if "auth" not in st.session_state:
        st.session_state["auth"] = False
    
    if not st.session_state["auth"]:
        user = st.text_input("Usuário")
        passwd = st.text_input("Senha", type="password")
        if st.button("Entrar"):
            if user in usuarios and usuarios[user]["senha"] == passwd:
                st.session_state["auth"] = True
                st.session_state["usuario"] = user
                st.session_state["perfil"] = usuarios[user].get("perfil", "usuario")
                registrar_acesso(user, True)
                st.rerun()
            else:
                registrar_acesso(user, False)
                st.error("Credenciais inválidas")
    else:
        st.write(f"👤 Usuário: {st.session_state['usuario']}")
        st.write(f"👥 Perfil: {st.session_state['perfil'].upper()}")
        
        # Menu de navegação
        st.markdown("---")
        st.subheader("Menu")
        
        # Botões de navegação
        if st.button("📊 Dashboard", use_container_width=True):
            st.session_state['pagina'] = "Dashboard"
            st.rerun()
            
        if st.button("📁 Adicionar CSV", use_container_width=True):
            st.session_state['pagina'] = "Upload"
            st.rerun()
            
        if st.session_state["perfil"] == "admin":
            if st.button("👥 Gerenciar Usuários", use_container_width=True):
                st.session_state['pagina'] = "Gerenciar Usuários"
                st.rerun()
        
        # Logout
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.clear()
            st.rerun()

# Se não estiver autenticado, para a execução
if not st.session_state.get("auth", False):
    st.stop()

usuario_logado = st.session_state["usuario"]
perfil = st.session_state["perfil"]

# --- Mapeamento fixo: IDs das instâncias para nomes amigáveis ---
map_id_nome = {
    "i-004aa9af94306175c": "APIM1",
    "i-03c02a18d07496f1a": "APIM2",
    "i-0ba770aa30f8325b5": "AUTH1",
    "i-0033c69668ebbc534": "BACK1",
    "i-0ea54825b577390a0": "BACK2",
    "i-01b1f326e63cb56f1": "BASTION1",
    "i-0737955cfc1e930f4": "BASTION2",
    "i-0fa1ce03a95c7c765": "BATCH1",
    "i-01107f87da0c4587a": "CONNECT1",
    "i-067b348d35193f49b": "DBJCARD1",
    "i-0a764aacd5769c2b4": "DBJCARD2",
    "i-0f5b41a7423c91f44": "DBPLAT1",
    "i-007287d000007eb93": "DBPLAT2",
    "i-02438c52a2db1aa73": "DEVAP1",
    "i-053e4a7e163c38a6b": "DEVDB1u",
    "i-0b5969cb24a49e8d0": "FRONT1",
    "i-09738848ac28e5c0f": "FRONT2",
    "i-029a66416ca0d6b76": "HAPIM1",
    "i-0dc17724754e7095e": "HFRONT1 UBUNTU",
    "i-083c47f691ab9b8fe": "IC1",
    "i-0f9e5a455d5579313": "JCARD1_UBUNTU",
    "i-0ad0d6d0dc56b6522": "JCARD2_UBUNTU",
    "i-0e9ef6ee101c397ae": "JS1",
    "i-00db97f03d8779f08": "OPENVAS1",
    "i-0b51a7838b33c7fd0": "PROM1",
    "i-00ad113f95f87d264": "QLIK1",
    "i-020924250769f0896": "SONAR1",
    "i-0b3e46b0ac947d23b": "WAZUH1",
    "i-0adfb9cc8689e8d7c": "WHAT1",
    "i-01e9fc10055930299": "ZABBIX1"
}

# --- Conteúdo Principal ---
if 'pagina' not in st.session_state:
    st.session_state['pagina'] = "Dashboard"

if st.session_state['pagina'] == "Dashboard":
    st.title("🔍 AWS Inspector Dashboard")
    st.markdown(f"👤 Usuário logado: **{usuario_logado}** — Perfil: **{perfil.upper()}**")

    if 'df' in st.session_state:
        df = st.session_state['df']
        
        # Debug: Mostrar colunas disponíveis
        st.write("Colunas disponíveis:", df.columns.tolist())
        
        # Renomear coluna
        df['InstanceId'] = df['Resource ID']
        df['Nome_Instancia'] = df['InstanceId'].map(map_id_nome)
        df['First Seen'] = pd.to_datetime(df['First Seen'])

        # Métricas principais
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total de Vulnerabilidades", len(df))
        with col2:
            st.metric("Instâncias Afetadas", df['Resource ID'].nunique())
        with col3:
            st.metric("Severidade Crítica", len(df[df['Severity'] == 'CRITICAL']))
        with col4:
            st.metric("Severidade Alta", len(df[df['Severity'] == 'HIGH']))

        # Filtros avançados
        st.markdown("### 🔍 Filtros")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            instancia_filtro = st.multiselect(
                "Filtrar por Instância",
                options=sorted(df['Nome_Instancia'].dropna().unique()),
                help="Selecione uma ou mais instâncias para filtrar"
            )
        
        with col2:
            severidade_filtro = st.multiselect(
                "Filtrar por Severidade",
                options=df['Severity'].unique(),
                help="Selecione os níveis de severidade para filtrar"
            )
        
        with col3:
            data_inicio = st.date_input(
                "Data Inicial",
                value=df['First Seen'].min().date(),
                min_value=df['First Seen'].min().date(),
                max_value=df['First Seen'].max().date()
            )
            data_fim = st.date_input(
                "Data Final",
                value=df['First Seen'].max().date(),
                min_value=df['First Seen'].min().date(),
                max_value=df['First Seen'].max().date()
            )

        # Aplicar filtros
        df_filtrado = df.copy()
        if instancia_filtro:
            df_filtrado = df_filtrado[df_filtrado['Nome_Instancia'].isin(instancia_filtro)]
        if severidade_filtro:
            df_filtrado = df_filtrado[df_filtrado['Severity'].isin(severidade_filtro)]
        df_filtrado = df_filtrado[
            (df_filtrado['First Seen'].dt.date >= data_inicio) &
            (df_filtrado['First Seen'].dt.date <= data_fim)
        ]

        # Visualizações
        st.markdown("### 📊 Análise de Vulnerabilidades")
        
        # Gráfico de vulnerabilidades por instância e severidade
        st.markdown("#### Vulnerabilidades por Instância e Severidade")
        chart_data = df.groupby(['Resource ID', 'Severity']).size().unstack(fill_value=0)
        st.bar_chart(chart_data)

        # Gráfico de linha temporal
        st.markdown("#### Evolução das Vulnerabilidades ao Longo do Tempo")
        if 'First Seen' in df.columns:
            timeline = df.groupby(df['First Seen'].dt.date).size()
            st.line_chart(timeline)
        else:
            st.warning("Coluna 'First Seen' não encontrada no DataFrame")

        # Distribuição de severidade
        st.markdown("#### Distribuição por Severidade")
        severidade_dist = df['Severity'].value_counts()
        st.bar_chart(severidade_dist)
        
        # Adicionar métricas de distribuição
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Crítica", severidade_dist.get('CRITICAL', 0))
        with col2:
            st.metric("Alta", severidade_dist.get('HIGH', 0))
        with col3:
            st.metric("Média", severidade_dist.get('MEDIUM', 0))
        with col4:
            st.metric("Baixa", severidade_dist.get('LOW', 0))

        # Top 10 vulnerabilidades mais comuns
        st.markdown("#### Top 10 Vulnerabilidades Mais Comuns")
        
        # Criar DataFrame com informações detalhadas das top 10 vulnerabilidades
        top_vulns = df_filtrado['Title'].value_counts().head(10)
        top_vulns_df = pd.DataFrame({
            'Vulnerabilidade': top_vulns.index,
            'Quantidade': top_vulns.values
        })
        
        # Adicionar informações de severidade para cada vulnerabilidade
        top_vulns_df['Severidade'] = top_vulns_df['Vulnerabilidade'].apply(
            lambda x: df_filtrado[df_filtrado['Title'] == x]['Severity'].mode().iloc[0]
        )
        
        # Ordenar por quantidade e severidade
        top_vulns_df = top_vulns_df.sort_values(['Quantidade', 'Severidade'], ascending=[False, False])
        
        # Exibir métricas
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Vulnerabilidade Mais Comum", top_vulns_df.iloc[0]['Vulnerabilidade'])
        with col2:
            st.metric("Total de Ocorrências", top_vulns_df.iloc[0]['Quantidade'])
        
        # Exibir gráfico
        st.bar_chart(top_vulns_df.set_index('Vulnerabilidade')['Quantidade'])
        
        # Exibir tabela detalhada
        st.markdown("##### Detalhes das Top 10 Vulnerabilidades")
        st.dataframe(
            top_vulns_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Vulnerabilidade": st.column_config.TextColumn(
                    "Vulnerabilidade",
                    width="large",
                    help="Nome da vulnerabilidade"
                ),
                "Quantidade": st.column_config.NumberColumn(
                    "Quantidade",
                    help="Número de ocorrências"
                ),
                "Severidade": st.column_config.TextColumn(
                    "Severidade",
                    help="Nível de severidade mais comum"
                )
            }
        )

        # Dados detalhados
        st.markdown("### 📋 Dados Detalhados")
        
        # Opções de visualização
        view_option = st.radio(
            "Escolha a visualização",
            ["Tabela Completa", "Resumo por Instância", "Resumo por Severidade"]
        )

        # Lista de colunas disponíveis
        colunas_disponiveis = df_filtrado.columns.tolist()
        colunas_para_exibir = [col for col in ['Nome_Instancia', 'Severity', 'Title', 'First Seen', 'Description'] 
                             if col in colunas_disponiveis]

        if view_option == "Tabela Completa":
            st.dataframe(
                df_filtrado[colunas_para_exibir].sort_values(['Severity', 'First Seen'], ascending=[False, False]),
                use_container_width=True,
                hide_index=True
            )
        elif view_option == "Resumo por Instância":
            resumo_instancia = df_filtrado.groupby('Nome_Instancia').agg({
                'Severity': lambda x: dict(x.value_counts()),
                'Title': 'count'
            }).reset_index()
            resumo_instancia.columns = ['Instância', 'Distribuição de Severidade', 'Total de Vulnerabilidades']
            st.dataframe(resumo_instancia, use_container_width=True, hide_index=True)
        else:
            resumo_severidade = df_filtrado.groupby('Severity').agg({
                'Nome_Instancia': 'nunique',
                'Title': 'count'
            }).reset_index()
            resumo_severidade.columns = ['Severidade', 'Instâncias Afetadas', 'Total de Vulnerabilidades']
            st.dataframe(resumo_severidade, use_container_width=True, hide_index=True)

        # Exportação
        st.markdown("### 📤 Exportação")
        col1, col2 = st.columns(2)
        with col1:
            csv = df_filtrado.to_csv(index=False).encode('utf-8')
            st.download_button(
                "⬇️ Baixar CSV Filtrado",
                data=csv,
                file_name="inspector_filtrado.csv",
                mime='text/csv'
            )
        with col2:
            if st.button("🔄 Limpar Filtros"):
                st.session_state['df'] = df
                st.rerun()

    else:
        st.info("Faça upload de um arquivo CSV através do menu lateral para visualizar o dashboard.")

elif st.session_state['pagina'] == "Upload":
    st.title("📁 Upload de CSV")
    
    uploaded_file = st.file_uploader("Selecione o arquivo CSV do AWS Inspector", type=['csv'])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.session_state['df'] = df
        st.success("CSV carregado com sucesso!")
        if st.button("Ir para Dashboard"):
            st.session_state['pagina'] = "Dashboard"
            st.rerun()

elif st.session_state['pagina'] == "Gerenciar Usuários" and perfil == "admin":
    st.title("👥 Gerenciamento de Usuários")
    
    # Criar duas colunas para o layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("Lista de Usuários")
        # Criar DataFrame para exibição
        usuarios_df = pd.DataFrame([
            {
                "Usuário": user,
                "Perfil": data["perfil"],
                "Último Acesso": data.get("ultimo_acesso", "Nunca")
            }
            for user, data in usuarios.items()
        ])
        
        if not usuarios_df.empty:
            st.dataframe(
                usuarios_df,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Nenhum usuário cadastrado.")
    
    with col2:
        st.subheader("Ações")
        if st.button("➕ Adicionar Novo Usuário", use_container_width=True):
            st.session_state['mostrar_form'] = True
        
        if st.session_state.get('mostrar_form', False):
            with st.form("novo_usuario_form"):
                st.subheader("Novo Usuário")
                novo_usuario = st.text_input("Nome do usuário")
                nova_senha = st.text_input("Senha", type="password")
                novo_perfil = st.selectbox("Perfil", ["usuario", "admin"])
                
                col1, col2 = st.columns(2)
                with col1:
                    submitted = st.form_submit_button("Salvar")
                with col2:
                    if st.form_submit_button("Cancelar"):
                        st.session_state['mostrar_form'] = False
                        st.rerun()
                
                if submitted:
                    if novo_usuario and nova_senha:
                        # Validar força da senha
                        senha_valida, mensagem = validar_senha(nova_senha)
                        if not senha_valida:
                            st.error(mensagem)
                        elif novo_usuario not in usuarios:
                            # Gerar hash da senha
                            senha_hash, salt = hash_senha(nova_senha)
                            usuarios[novo_usuario] = {
                                "senha": senha_hash,
                                "salt": salt,
                                "perfil": novo_perfil,
                                "ultimo_acesso": "Nunca",
                                "data_criacao": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            salvar_usuarios(usuarios)
                            st.success("Usuário adicionado com sucesso!")
                            st.session_state['mostrar_form'] = False
                            st.rerun()
                        else:
                            st.error("Usuário já existe!")
                    else:
                        st.error("Preencha todos os campos!")
    
    # Seção de ações em massa
    st.markdown("---")
    st.subheader("Ações em Massa")
    
    # Seleção de usuários para ações em massa
    usuarios_selecionados = st.multiselect(
        "Selecione os usuários para ações em massa",
        options=usuarios.keys(),
        format_func=lambda x: f"{x} ({usuarios[x]['perfil']})"
    )
    
    if usuarios_selecionados:
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Alterar Perfil", key="alterar_perfil"):
                novo_perfil = st.selectbox(
                    "Novo Perfil",
                    ["usuario", "admin"],
                    key="novo_perfil_massa"
                )
                if st.button("Confirmar Alteração"):
                    for user in usuarios_selecionados:
                        usuarios[user]["perfil"] = novo_perfil
                    salvar_usuarios(usuarios)
                    st.success("Perfis alterados com sucesso!")
                    st.rerun()
        
        with col2:
            if st.button("Remover Usuários", key="remover_usuarios"):
                if st.button("Confirmar Remoção"):
                    for user in usuarios_selecionados:
                        del usuarios[user]
                    salvar_usuarios(usuarios)
                    st.success("Usuários removidos com sucesso!")
                    st.rerun()
else:
    st.warning("Você não tem permissão para acessar esta página.")
