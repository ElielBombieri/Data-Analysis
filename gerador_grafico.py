import matplotlib.pyplot as plt
import pandas as pd
import json 
import numpy as np
import os

os.mkdir('web')
os.mkdir('web/assets')


print('='*170)
delimitador = input('Digite o delimitador dos arquivos csv: ')

with open('config.json', 'r', encoding='utf-8') as arquivo:
    dados_do_json = json.load(arquivo)

print("\n--- Acessando os dados ---")

for i in range(len(dados_do_json)):
    arquivo_entrada = dados_do_json[i]['arquivo_entrada']
    coluna_x = dados_do_json[i]['coluna_x']
    coluna_y = dados_do_json[i]['coluna_y']
    titulo = dados_do_json[i]['titulo']
    tipo = dados_do_json[i]['tipo']

    df = pd.read_csv(arquivo_entrada, sep=delimitador , engine='python')
    
    print(f"Arquivo de entrada: {arquivo_entrada}")

    if(arquivo_entrada == 'dataframes/Dados_gerais.csv'):
        nro_ativos = (
            df['Número de ativos']
            .iloc[0]
            .astype(int)
        )
        qtd_vulnerabilidades = (
            df[coluna_y]
            .iloc[0]
            .astype(int) 
        )
        qtd_vulnerabilidades_cve = (
            df['Quantia total de vulnerabilidades com CVE']
            .iloc[0]
            .astype(int)
        )
        qtd_cve_unico = (
            df['Quantia de CVEs únicos']
            .iloc[0]
            .astype(int)
        )
        qtd_vulnerabilidades_unicas = (
            df['Quantia total de vulnerabilidades únicas']
            .iloc[0]
            .astype(int)
        )

    elif arquivo_entrada == 'dataframes/Quantia_de_cada_criticidade.csv':
        criticidades = ['Baixa ', 'Media ', 'Alta ', 'Critica ']
        criticidade = {}
        for crit in criticidades:
            valor = df.loc[df['Criticidade Unica'] == crit, 'Quantia de vulnerabilidade']
            criticidade[crit.lower()] = int(valor.values[0]) if not valor.empty else 0

    elif arquivo_entrada == 'dataframes/Quantia_de_cada_criticidade_com_CVE.csv':
        criticidades = ['Baixa ', 'Media ', 'Alta ', 'Critica ']
        criticidade_cve = {}
        for crit in criticidades:
            valor = df.loc[df['Criticidade Unica'] == crit, 'Quantia de vulnerabilidade']
            criticidade_cve[crit.lower()] = int(valor.values[0]) if not valor.empty else 0
    
    elif arquivo_entrada == 'dataframes/Vulnerabilidades_por_OS.csv':
        OS = ['Outro', 'Linux', 'Windows']
        criticidade_os = {}
        for i in OS:
            valor = df.loc[df['Sistema Operacional'] == i, 'Contagem']
            criticidade_os[i.lower()] = int(valor.values[0]) if not valor.empty else 0

    else:
        if(tipo == 2):
            if(arquivo_entrada == 'dataframes/Ocorrencias_por_criticidade.csv'):
                for j in range(len(df)):
                    Crit_nvt_name1 = f'({df['Quantia de vulnerabilidade'].astype(str).iloc[j-4]}) ' + df['NVT Name'].astype(str).iloc[j-4]   
                    Crit_nvt_name2 = f'({df['Quantia de vulnerabilidade'].astype(str).iloc[j-3]}) ' + df['NVT Name'].astype(str).iloc[j-3]   
                    Crit_nvt_name3 = f'({df['Quantia de vulnerabilidade'].astype(str).iloc[j-2]}) ' + df['NVT Name'].astype(str).iloc[j-2]   
                    Crit_nvt_name4 = f'({df['Quantia de vulnerabilidade'].astype(str).iloc[j-1]}) ' + df['NVT Name'].astype(str).iloc[j-1]   
                    Crit_nvt_name5 = f'({df['Quantia de vulnerabilidade'].astype(str).iloc[j]}) '   + df['NVT Name'].astype(str).iloc[j]    
            if(arquivo_entrada == 'dataframes/Ocorrencias_por_quantidade.csv'):
                for k in range(len(df)):
                    Qtd_nvt_name1 = df['NVT Name'].astype(str).iloc[k-4]  
                    Qtd_nvt_name2 = df['NVT Name'].astype(str).iloc[k-3]
                    Qtd_nvt_name3 = df['NVT Name'].astype(str).iloc[k-2]
                    Qtd_nvt_name4 = df['NVT Name'].astype(str).iloc[k-1]
                    Qtd_nvt_name5 = df['NVT Name'].astype(str).iloc[k]
            if(arquivo_entrada == 'dataframes/Vulnerabilidades_por_quantia.csv'):
                for l in range(len(df)):
                    Cve_nvt_name1 = f'({df['ano de lançamento - CVE'].astype(str).iloc[l-4]}) ' + df['NVT Name'].astype(str).iloc[l-4] 
                    Cve_nvt_name2 = f'({df['ano de lançamento - CVE'].astype(str).iloc[l-3]}) ' + df['NVT Name'].astype(str).iloc[l-3]
                    Cve_nvt_name3 = f'({df['ano de lançamento - CVE'].astype(str).iloc[l-2]}) ' + df['NVT Name'].astype(str).iloc[l-2]
                    Cve_nvt_name4 = f'({df['ano de lançamento - CVE'].astype(str).iloc[l-1]}) ' + df['NVT Name'].astype(str).iloc[l-1]
                    Cve_nvt_name5 = f'({df['ano de lançamento - CVE'].astype(str).iloc[l]}) ' + df['NVT Name'].astype(str).iloc[l]

            fig, ax = plt.subplots(figsize=(9,6))
            wedges, texts, autotexts = ax.pie(
                df[coluna_y], 
                autopct=lambda v:f"{df[coluna_y].sum()*v/100:.3f}", 
                textprops={'color':"#ffffff", 'fontsize':14}
            )
            ax.set_title(titulo, fontsize=20, color="#ffffff", fontweight="bold")
            plt.tight_layout()
            plt.savefig(f"web/assets/Figure_{i}.png", transparent=True)
        elif(tipo == 1):
            fig, ax = plt.subplots(figsize=(7,5))
            ax.bar(df[coluna_x], df[coluna_y], color="#8DC6FF")
            ax.set_title(titulo, fontsize=20, color="#ffffff", fontweight="bold")
            ax.set_xlabel(coluna_x, fontsize=15, color="#ffffff")
            ax.set_ylabel(coluna_y, fontsize=15, color="#ffffff")
            for spine in ax.spines.values():
                spine.set_visible(False)
            plt.setp(ax.get_xticklabels(), rotation=45, ha="right", color="#ffffff")
            plt.tight_layout()
            plt.savefig(f"web/assets/Figure_{i}.png", bbox_inches='tight', transparent=True)

        else:
            print('='*170)
            print('Opção incorreta')
            print('='*170)


css = """


main{
    padding: 1% 5%;
    margin: 0%;
    background: #001a35;
}

.dados_gerais{
    display: flex;
    justify-content: space-between;
    align-items: top;
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.title{
    text-align: center;
    padding: 1rem;
    font-family: "Tomorrow", sans-serif;
    font-weight: bold;
    font-size: 2rem;
    margin-top: 0.5rem;
    color: #ffffff;
}

.bloco_dados {
    background: #0154ad;
    border-radius: 12px;
    padding: 1rem;
    margin: 0.5rem 0;
    transition: transform 0.2s;
}

.linux:hover,
.outros:hover,
.windows:hover,
.bloco_baixa:hover,
.bloco_media:hover,
.bloco_alta:hover,
.bloco_critica:hover,
.bloco_dados:hover {
    transform: translateY(-5px) scale(1.03);
    box-shadow: 0 8px 24px rgba(255, 255, 255, 0.17);
}

.bloco_dados h3:not(.dado) {
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    text-align: center;
    color: #ffffff;
}

.sistemas_operacionais{
    display: flex;
    justify-content: space-between;
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.linux,
.outros,
.windows{
    background: #0154ad;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.10);
    padding: 1rem;
    margin: 0.5rem 0;
    transition: transform 0.2s;
}

.linux:not(.title_os),
.outros:not(.title_os),
.windows:not(.title_os) {
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    text-align: center;
    color: #ffffff;
}

.logo{
    width: 6rem;
    height: auto;
}

.dado{
    font-family: "Tomorrow", sans-serif;
    letter-spacing: 2px;
    font-size: 4rem;
    font-weight: bold;
    border-style: solid;
    text-align: center;
    border-radius: 8px;
    color: #272727;
    border-color: #fff;
    border: 1px solid #ddd;
    background-color: #fff;
    box-shadow: 0 4px 16px rgba(26, 26, 26, 0.15);
}

.bloco_baixa {
    background: #51925a;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.10);
    padding: 1rem;
    margin: 0.5rem 0;
    transition: transform 0.2s;
}

.bloco_baixa h3:not(.dado) {
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    text-align: center;
    color: #31ff4c;
}
.bloco_media {
    background: #a8aa19;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.10);
    padding: 1rem;
    margin: 0.5rem 0;
    transition: transform 0.2s;
}

.bloco_media h3:not(.dado) {
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    text-align: center;
    color: #fcff5b;
}
.bloco_alta {
    background: #be823c;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.10);
    padding: 1rem;
    margin: 0.5rem 0;
    transition: transform 0.2s;
}

.bloco_alta h3:not(.dado) {
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    text-align: center;
    color: #ffd9ad;
}

.bloco_critica {
    background: #802929;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.10);
    padding: 1rem;
    margin: 0.5rem 0;
    transition: transform 0.2s;
}

.bloco_critica h3:not(.dado) {
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    text-align: center;
    color: #ff9393;
}


.Geral{
    gap: 1%;
}

.pizza,
.barras {
    display: flex;
    align-items: center;
}

.pizza_line1,
.pizza_line2,
.pizza_line3,
.barras__line1,
.barras__line2,
.barras__line3 {
    display: flex;
    justify-content: center;
    flex-direction: row;
    gap: 1.5rem;
    padding: 1.5rem;    
}

.imagem {
    border-radius: 8px;
    background: #0154ad;
    width: 700px;
    height: 450px;
}

.pizza_line1,
.pizza_line2,
.pizza_line3,
.barras__line1,
.barras__line2,
.barras__line3 {
    gap: 2rem;
    background-color: linear-gradient(135deg, #e3f0ff 0%, #b3d1ff 100%);
}


.description {
    width: 700px;
    max-height: 450px;
    color: #f6f6f6;
    font-family: "Tomorrow", sans-serif;
    font-size: 1.5rem;
    padding: 0.5rem;
}


"""

html = f"""<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Gráficos</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Michroma&family=Tomorrow:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">
    <link class="logo" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
  </head>
  <body>
    <header>
    </header>
    <main>
        <div class="Geral">
            <h1 class="title">Dados Gerais</h1>
            <div class="row dados_gerais">
                <div class="col bloco_dados">
                    <h3 class="dado">{nro_ativos}</h3>    
                    <h3 class="col-lg-12">Quantidade de ativos scaneados</h3> 
                </div>
                <div class="col bloco_dados">
                    <h3 class="dado">{qtd_vulnerabilidades}</h3>
                    <h3 class="col-lg-12">Quantidade de vulnerabilidades encontradas</h3>    
                </div>
                <div class="col bloco_dados">
                    <h3 class="dado">{qtd_vulnerabilidades_cve}</h3>
                    <h3 class="col-lg-12">quantidade de vulnerabilidades com CVE</h3>    
                </div>
                <div class="col bloco_dados">
                    <h3 class="dado">{qtd_cve_unico}</h3>                    
                    <h3 class="col-lg-12">Quantidade de vulnerabilidades unicas com CVE</h3>    
                </div>
                <div class="col bloco_dados">
                    <h3 class="dado">{qtd_vulnerabilidades_unicas}</h3>
                    <h3 class="col-lg-12">quantidade de vulnerabilidades unicas encontradas</h3>    
                </div>
            </div>
            <h2 class="title">Distribuição de ativos por SO</h2>
            <div class="row sistemas_operacionais">
                <div class="col windows">
                    <img class="logo" src="https://upload.wikimedia.org/wikipedia/commons/c/c1/Windows_icon_logo.png" alt="">
                    <h2 class="title_os">Windows</h2>
                    <h3 class="dado">{criticidade_os['windows']}</h3>
                </div>
                <div class="col linux">
                    <img class="logo" src="https://cdn-icons-png.flaticon.com/512/25/25719.png" alt="">
                    <h2 class="title_os">Linux</h2>
                    <h3 class="dado">{criticidade_os['linux']}</h3>
                </div>
                <div class="col outros">
                    <img class="logo" src="https://cdn-icons-png.flaticon.com/512/5895/5895032.png" alt="">
                    <h2 class="title_os">Outros</h2>
                    <h3 class="dado">{criticidade_os['outro']}</h3>
                </div>
            </div>
            <h1 class="title">Distribuição de vulnerabilidades por criticidade</h1>
            <div class="row dados_gerais">
                <div class="col bloco_baixa">
                    <h3 class="dado">{criticidade['baixa ']}</h3>    
                    <h3 class="col-lg-12">Baixa</h3> 
                </div>
                <div class="col bloco_media">
                    <h3 class="dado">{criticidade['media ']}</h3>
                    <h3 class="col-lg-12">Media</h3>    
                </div>
                <div class="col bloco_alta">
                    <h3 class="dado">{criticidade['alta ']}</h3>
                    <h3 class="col-lg-12">Alta</h3>    
                </div>
                <div class="col bloco_critica">
                    <h3 class="dado">{criticidade['critica ']}</h3>                    
                    <h3 class="col-lg-12">Critica</h3>    
                </div>
            </div>
            <h1 class="title">Distribuição de vulnerabilidades com CVE por criticidade com CVE</h1>
            <div class="row dados_gerais">
                <div class="col bloco_baixa">
                    <h3 class="dado">{criticidade_cve['baixa ']}</h3>    
                    <h3 class="col-lg-12">Baixa</h3> 
                </div>
                <div class="col bloco_media">
                    <h3 class="dado">{criticidade_cve['media ']}</h3>
                    <h3 class="col-lg-12">Media</h3>    
                </div>
                <div class="col bloco_alta">
                    <h3 class="dado">{criticidade_cve['alta ']}</h3>
                    <h3 class="col-lg-12">Alta</h3>    
                </div>
                <div class="col bloco_critica">
                    <h3 class="dado">{criticidade_cve['critica ']}</h3>                    
                    <h3 class="col-lg-12">Critica</h3>    
                </div>
            </div>
            <div class="row barras">
                <div class="col-lg-12 barras__line1">
                    <img class="imagem" src="assets/Figure_1.png" alt="">
                    <img class="imagem" src="assets/Figure_2.png" alt="">
                </div>
                <div class="col-lg-12 barras__line2">
                    <img class="imagem" src="assets/Figure_3.png" alt="">
                    <img class="imagem" src="assets/Figure_4.png" alt="">
                </div>
            </div>
            <div class="row pizza">
                <div class="col-lg-12 pizza_line1">
                    <img class="imagem" src="assets/Figure_5.png" alt="">
                    <div>
                        <h3 class="description">1. {Crit_nvt_name1}</h3>
                        <h3 class="description">2. {Crit_nvt_name2}</h3>
                        <h3 class="description">3. {Crit_nvt_name3}</h3>
                        <h3 class="description">4. {Crit_nvt_name4}</h3>
                        <h3 class="description">5. {Crit_nvt_name5}</h3>                        
                    </div>
                </div>
                <div class="col-lg-12 pizza_line2">
                    <img class="imagem" src="assets/Figure_6.png" alt="">
                    <div>
                        <h3 class="description">1. {Qtd_nvt_name1}</h3>
                        <h3 class="description">2. {Qtd_nvt_name2}</h3>
                        <h3 class="description">3. {Qtd_nvt_name3}</h3>
                        <h3 class="description">4. {Qtd_nvt_name4}</h3>
                        <h3 class="description">5. {Qtd_nvt_name5}</h3>                        
                    </div>
                </div>
                <div class="col-lg-12 pizza_line3">
                    <img class="imagem" src="assets/Figure_10.png" alt="">
                    <div>
                        <h3 class="description">1. {Cve_nvt_name1}</h3>
                        <h3 class="description">2. {Cve_nvt_name2}</h3>
                        <h3 class="description">3. {Cve_nvt_name3}</h3>
                        <h3 class="description">4. {Cve_nvt_name4}</h3> 
                        <h3 class="description">5. {Cve_nvt_name5}</h3>                        
                    </div>
                </div>
            </div>
        </div>
    </main>
    <footer></footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI" crossorigin="anonymous"></script>
  </body>
</html>"""

with open('web/index.html', 'w', encoding='utf-8') as arquivo_html:
    arquivo_html.write(html)

with open('web/style.css', 'w', encoding='utf-8') as arquivo_html:
    arquivo_html.write(css)
