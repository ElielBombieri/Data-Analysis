import pandas as pd
import os 
from datetime import date

#Conexão
caminho = 'database.csv' #input("Digite o caminho do arquivo:")
delimitador = '§'  #input("Digite o caracter que delimita as colunas do csv:") 
df = pd.read_csv(caminho, sep=delimitador)


#Colunas artificiais
df['Quantia_Vulnerabilidade'] = df['CVEs'].str.count('CVE').fillna(1)
df['Criticidade'] = df['CVSS'].apply(lambda x: 'Crítica' if x > 8.9 else ('Alta' if x > 6.9 else ('Média' if x > 3.9 else 'Baixa')))

#df filtrado

df_regra_apenas_CVE = df["CVEs"].fillna(0) != 0
df_apenas_com_cve = df[df_regra_apenas_CVE]
data = date.today().year - 1
df_regra_ano_passado = df_apenas_com_cve['CVEs'].str[4:8].astype(int) >= data

df_data_cve_menor_que_2anos = df_apenas_com_cve[df_regra_ano_passado]

print(data)



#Consultas
df_total_vulnerabilidades = df['Quantia_Vulnerabilidade'].sum()
df_total_vulnerabilidades_cve = df_apenas_com_cve['Quantia_Vulnerabilidade'].sum()
df_ip_por_cvss = df[['IP','CVSS', 'Criticidade']].sort_values('CVSS', ascending=False).head(5)
df_agg_criticidade_ip = df.groupby('IP')['Criticidade'].agg(lambda x: ', '.join(x)).astype(str)
df_quantia_por_ip = df.groupby('IP')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False).head(5)
df_quantia_por_vulnerabilidade = df.groupby('NVT Name')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False).head(5)
df_quantia_por_criticidade = df.groupby('Criticidade')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False)
df_quantia_por_criticidade_cve = df_apenas_com_cve.groupby('Criticidade')['Quantia_Vulnerabilidade'].sum().sort_values(ascending=False)


#Finalização

#PLANILHA 
# os.mkdir('pasta_de_dados')
# with open("pasta_de_dados/Dados_Gerais.txt", "w") as arquivo:
#     print(df_dadosGerais, file=arquivo)


# df_dadosGerais = f'\nnumero de ativos: {df_qtdIP}'\
#                 f'\nQuantia total de vulnerabilidades: {df_totVulnerabilidades}'\
#                 '\n'
# df_ipFreq.to_csv('pasta_de_dados/top5_ip_por_vulnerabilidade.csv')
# df_ipCvss.to_csv('pasta_de_dados/top5_ip_por_CVSS.csv', index=False)
#df_VulnerabilidadeQtd.to_csv('pasta_de_dados/Top5_ocorrencias_por_quantidade.csv')
