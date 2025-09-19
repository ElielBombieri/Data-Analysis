import pandas as pd
from datetime import date

#Conexão
print('='*170)
print('Mova o dataframe .csv para o mesmo nivel de diretório deste programa')
caminho = input('Digite o nome do arquivo:')
delimitador = input('\nDigite o caracter que delimita as colunas do csv:') 
print('='*170)
df = pd.read_csv(caminho, sep=delimitador)

#limpeza do df (colunas não utilizadas)
df = df.drop([
    'Hostname', 'Port', 'Port Protocol', 'Severity',
    'QoD','Summary', 'Solution Type', 'Impact', 'Solution',
    'Vulnerability Insight', 'Vulnerability Detection Method'], axis=1)

#Colunas artificiais
df['Quantia de vulnerabilidade'] = df['CVEs'].str.count('CVE').fillna(1)

df['Criticidade Unica'] = df['CVSS'].apply(
    lambda x: 
    'Critica ' if x > 8.9 
    else (
        'Alta ' if x > 6.9 
        else (
            'Media ' if x > 3.9 
                else 'Baixa ')))

df['Criticidade'] = df['CVSS'].apply(
    lambda x: 
    'Critica ' if x > 8.9 
    else (
        'Alta ' if x > 6.9 
        else (
            'Media ' if x > 3.9 
                else 'Baixa '))) * df['Quantia de vulnerabilidade'].astype(int)

df['Criticidade_tot'] = df.groupby('IP')['Criticidade'].transform(
    lambda x:
      ' '.join(x)
      ).astype(str)

df['Criticidade detalhamento'] = ('baixa: ' + df['Criticidade_tot'].str.count('Baixa').astype(str) 
+ ' Media: '+ df['Criticidade_tot'].str.count('Media').astype(str) 
+ ' Alta: '+ df['Criticidade_tot'].str.count('Alta').astype(str) 
+ ' Critica: ' + df['Criticidade_tot'].str.count('Critica').astype(str))

df = df.drop('Criticidade_tot', axis=1)

df['Concat_OS'] = df['Specific Result'].astype(str) + df['Affected Software/OS'].astype(str)
df['Sistema_Operacional'] = df['Concat_OS'].astype(str).apply(
    lambda x: 
        'Linux'
        if 'Linux' in x or 'GNU' in x or 'Debian' in x
        else(
            'Windows'
            if 'Windows' in x
            else(
                'Outro'
            )
        )
    )
df = df.drop('Concat_OS', axis=1)

#df filtrados
df_apenas_com_cve = df[df['CVEs'].fillna(0) != 0]
df_apenas_com_cve['ano de lançamento - CVE'] = df_apenas_com_cve['CVEs'].str[4:8].astype(int)
df_cve_ano = df_apenas_com_cve[df_apenas_com_cve['ano de lançamento - CVE'] <= (date.today().year-1)]
df_cve_unico = df_apenas_com_cve.drop_duplicates(subset=['CVEs', 'Quantia de vulnerabilidade'])
df_vulnerabilidades_unicas = df.drop_duplicates(subset=['NVT Name'])

#Consultas
top_ip_por_cvss = df[
        ['IP','CVSS', 'Criticidade detalhamento', 'Quantia de vulnerabilidade']
    ].sort_values(by=['CVSS', 'Quantia de vulnerabilidade'], ascending=False).head(5)

top_quantia_por_ip = df.groupby(['IP', 'Criticidade detalhamento'])['Quantia de vulnerabilidade'].sum().sort_values(ascending=False).head(5)
top_quantia_por_vulnerabilidade = df.groupby('NVT Name')['Quantia de vulnerabilidade'].sum().sort_values(ascending=False).head(5)
top_quantia_por_criticidade = df.groupby('Criticidade Unica')['Quantia de vulnerabilidade'].sum().sort_values(ascending=False)
top_quantia_por_criticidade_cve = df_apenas_com_cve.groupby('Criticidade Unica')['Quantia de vulnerabilidade'].sum().sort_values(ascending=False)

top_quantia_por_vulnerabilidade_1ano = df_cve_ano.groupby(
        ['NVT Name', 'ano de lançamento - CVE']
    )['Quantia de vulnerabilidade'].sum().sort_values(ascending=False).head(5)

top_ip_por_epss = df[
        ['IP', 'NVT Name', 'Exploit Prediction Scoring System - EPSS']
    ].fillna(0).sort_values('Exploit Prediction Scoring System - EPSS' ,ascending=False).head(5)

top_ip_por_kev_cvss = df[
        ['IP', 'Known Exploited Vulnerability', 'CVSS']
    ].fillna(0).sort_values(by=['Known Exploited Vulnerability','CVSS'], ascending=False).head(5)

top_ocorrencias_por_criticidade = df.groupby(
        ['NVT Name', 'CVSS']
    )['Quantia de vulnerabilidade'].sum().reset_index().sort_values(by=['CVSS', 'Quantia de vulnerabilidade'], ascending=False).head(5)


total_ip_com_KEV = df[
        df['Known Exploited Vulnerability'].fillna('0') != '0'
    ][
        ['IP', 'Known Exploited Vulnerability', 'CVEs', 'Criticidade detalhamento']
    ]

#totais
total_de_os = df.groupby('Sistema_Operacional')['Quantia de vulnerabilidade'].sum().sort_index(ascending=False)
total_vulnerabilidades = df['Quantia de vulnerabilidade'].sum()
total_ip = len(df.drop_duplicates(subset=['IP']))
total_vulnerabilidades_cve = df_apenas_com_cve['Quantia de vulnerabilidade'].sum()
total_de_cve_unicos = df_cve_unico['Quantia de vulnerabilidade'].sum()
total_vulnerabilidades_unicas = df_vulnerabilidades_unicas['Quantia de vulnerabilidade'].sum()

#variavel com o agrupamento dos dados
dados_otimizados = '_'*30+\
                '\nDados Gerais do Dataframe\n'\
                f'\nNúmero de ativos: {total_ip}'\
                f'\nQuantia total de vulnerabilidades: {total_vulnerabilidades}'\
                f'\nQuantia total de vulnerabilidades com CVE: {total_vulnerabilidades_cve}'\
                f'\nQuantia de CVEs únicos: {total_de_cve_unicos}'\
                f'\nQuantia total de vulnerabilidades únicas: {total_vulnerabilidades_unicas}\n'\
                +'_'*30+\
                f'\nTop 5 IPs por quantia de vulnerabilidades\n\n {top_quantia_por_ip.to_string()}\n'\
                +'_'*30+\
                f'\nTop 5 IPs por criticidade\n\n{top_ip_por_cvss.to_string(index=False)}\n'\
                +'_'*30+\
                f'\nTop 5 ocorrencias por quantidade\n\n{top_quantia_por_vulnerabilidade.to_string()}\n'\
                +'_'*30+\
                f'\nQuantia de cada criticidade \n\n{top_quantia_por_criticidade.to_string()}\n'\
                +'_'*30+\
                f'\nQuantia de cada criticidade com CVE \n\n{top_quantia_por_criticidade_cve.to_string()}\n'\
                +'_'*30+\
                f'\nTop 5 vulnerabilidades com mais de um ano de lançamento \n\n{top_quantia_por_vulnerabilidade_1ano.to_string()}\n'\
                +'_'*30+\
                f'\nTop 5 IP por EPSS \n\n{top_ip_por_epss.to_string(index=False)}\n'\
                +'_'*30+\
                f'\nTop 5 IP por KEV e CVSS\n\n{top_ip_por_kev_cvss.to_string(index=False)}\n'\
                +'_'*30+\
                f'\nTop 5 vulnerabilidades por CVSS\n\n{top_ocorrencias_por_criticidade.to_string(index=False)}\n'\
                +'_'*30+\
                f'\nQuantia de vulnerabilidade por sistema operacional\n\n{total_de_os.to_string()}\n'\
                +'_'*30+\
                f'\nIPs que possuem KEV\n\n{total_ip_com_KEV.to_string(index=False)}\n'                

#Finalização 
with open(f'Dados_otimizados_{caminho}.txt', 'w', encoding='utf-8') as arquivo:
    print(dados_otimizados, file=arquivo)

print('='*170)
print('\nArquivo com os dados, criado no mesmo diretório desse script\n')
print('='*170)