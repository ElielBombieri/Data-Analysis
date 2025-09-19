import pandas as pd
import os 
from datetime import date

#Conexão
caminho = 'database.csv' #input("Digite o caminho do arquivo:")
delimitador = '§'  #input("Digite o caracter que delimita as colunas do csv:") 
df = pd.read_csv(caminho, sep=delimitador)

#limpeza do df

df = df.drop(['Hostname', 'Port', 'Port Protocol', 'Severity', 'QoD','Summary', 'MITRE', 'Solution Type', 'Impact', 'Solution', 'Vulnerability Insight', 'Vulnerability Detection Method'], axis=1)


#Colunas artificiais
df['Quantia_Vulnerabilidade'] = df['CVEs'].str.count('CVE').fillna(1)

df['CriticidadeUnica'] = df['CVSS'].apply(lambda x: 'Crítica ' if x > 8.9 else ('Alta ' if x > 6.9 else ('Média ' if x > 3.9 else 'Baixa ')))
df['Criticidade'] = df['CVSS'].apply(lambda x: 'Crítica ' if x > 8.9 else ('Alta ' if x > 6.9 else ('Média ' if x > 3.9 else 'Baixa ')))*df['Quantia_Vulnerabilidade'].astype(int)
df['Criticidade_tot'] = df.groupby('IP')['Criticidade'].transform(lambda x: ' '.join(x)).astype(str)
df['CriticidadeCount'] = 'baixa: ' + df['Criticidade_tot'].str.count('Baixa').astype(str) + ' Média: '+ df['Criticidade_tot'].str.count('Média').astype(str) + ' Alta: '+ df['Criticidade_tot'].str.count('Alta').astype(str) + ' Crítica: ' + df['Criticidade_tot'].str.count('Crítica').astype(str)
df = df.drop('Criticidade_tot', axis=1)
df['KVEcount'] = df['Known Exploited Vulnerability'].astype(str).str.count('CVE').fillna(0)
df['Sistema_Operacional'] = df['Specific Result'].apply(
    lambda x: 
        'Linux'
        if 'linux' in x or 'GNU' in 'x' or 'Debian' in x
        else(
            'Windows'
            if 'Windows' in x
            else(
                'Outro'
            )
        )
    )
#df filtrados e regras
rgr_apenas_CVE = df["CVEs"].fillna(0) != 0
df_apenas_com_cve = df[rgr_apenas_CVE]

ano_passado = date.today().year - 1
df_apenas_com_cve['ano_cve'] = df_apenas_com_cve['CVEs'].str[4:8].astype(int)
df_apenas_com_cve['idade_cve'] = (date.today().year - df_apenas_com_cve['ano_cve']).astype(str) + ' Anos' 
df_cve_com_mais_de_um_ano = df_apenas_com_cve[df_apenas_com_cve['ano_cve'] <= (date.today().year-1)]

df_cve_unico = df_apenas_com_cve.drop_duplicates(subset=['CVEs', 'Quantia_Vulnerabilidade'])

df_vulnerabilidades_unicas = df.drop_duplicates(subset=['NVT Name'])
#Consultas
total_vulnerabilidades = df['Quantia_Vulnerabilidade'].sum()
total_ip = len(df.drop_duplicates(subset=['IP']))
total_vulnerabilidades_cve = df_apenas_com_cve['Quantia_Vulnerabilidade'].sum()
total_de_cve_unicos = df_cve_unico['Quantia_Vulnerabilidade'].sum()
total_vulnerabilidades_unicas = df_vulnerabilidades_unicas['Quantia_Vulnerabilidade'].sum()
total_de_os = df.groupby('Sistema_Operacional')['Quantia_Vulnerabilidade'].sum()
top_dadosGerais = f'Dados Gerais do Dataframe\n'\
                f'\nNumero de ativos: {total_ip}'\
                f'\nQuantia total de vulnerabilidades: {total_vulnerabilidades}'\
                f'\nQuantia total de vulnerabilidades com CVE: {total_vulnerabilidades_cve}'\
                f'\nQuantia de CVEs unicos: {total_de_cve_unicos}'\
                f'\nQuantia total de vulnerabilidades unicas: {total_vulnerabilidades_unicas}'\

top_ip_por_cvss = df[['IP','CVSS', 'CriticidadeCount']].sort_values('CVSS', ascending=False).head(5)
top_quantia_por_ip = df.groupby(['IP', 'CriticidadeCount'])['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False).head(5)
top_quantia_por_vulnerabilidade = df.groupby('NVT Name')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False).head(5)
top_quantia_por_criticidade = df.groupby('CriticidadeUnica')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False)
top_quantia_por_criticidade_cve = df_apenas_com_cve.groupby('CriticidadeUnica')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False)
top_quantia_por_vulnerabilidade_com_mais_de_um_ano = df_cve_com_mais_de_um_ano.groupby(['NVT Name', 'ano_cve', 'idade_cve'])['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False).head(5)
top_ip_por_epss = df[['IP', 'NVT Name', 'Exploit Prediction Scoring System - EPSS']].fillna(0).sort_values('Exploit Prediction Scoring System - EPSS' ,ascending=False).head(5)
top_ip_por_kev_cvss = df[['IP', 'KVEcount', 'CVSS']].fillna(0).sort_values(by=['KVEcount','CVSS'], ascending=False).head(5)
top_ocorrencias_por_criticidade = df.groupby(['NVT Name', 'CVSS'])['Quantia_Vulnerabilidade'].sum().reset_index().sort_values(by=['CVSS'], ascending=False).head(5)

#testes

rgr_remove_linux = df['Sistema_Operacional'] != 'Linux'

df[rgr_remove_linux][['Specific Result','Sistema_Operacional']].to_csv('teste.csv')

#Finalização 
os.mkdir('Pasta_de_dados')

with open("pasta_de_dados/Dados_Gerais.txt", "w") as arquivo:
    print(top_dadosGerais, file=arquivo)

top_quantia_por_ip.to_csv('pasta_de_dados/Top5_ip_por_quantia_de_vulnerabilidade.csv')
top_ip_por_cvss.to_csv('pasta_de_dados/Top5_ip_por_CVSS.csv', index=False)
top_quantia_por_vulnerabilidade.to_csv('pasta_de_dados/Top5_ocorrencias_por_quantidade.csv')
top_quantia_por_criticidade.to_csv('pasta_de_dados/Quantia_de_cada_criticidade.csv')
top_quantia_por_criticidade_cve.to_csv('pasta_de_dados/Quantia_de_cada_criticidade_com_CVE.csv')
top_quantia_por_vulnerabilidade_com_mais_de_um_ano.to_csv('pasta_de_dados/Top5_vulnerabilidades_com_mais_de_um_ano_de_lancamento.csv')
top_ip_por_epss.to_csv('pasta_de_dados/Top5_ip_por_epss.csv', index=False)
top_ip_por_kev_cvss.to_csv('pasta_de_dados/Top5_ip_por_kve_cvss.csv', index=False)
top_ocorrencias_por_criticidade.to_csv('pasta_de_dados/Top5_vulnerabilidades_por_cvss.csv')
total_de_os.to_csv('pasta_de_dados/Quantia_de_vulnerabilidade_por_os.csv')


print('\n\n\nPasta criada com os dados, no mesmo diretório desse script\n\n\n')