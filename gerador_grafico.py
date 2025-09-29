import matplotlib.pyplot as plt
import pandas as pd
import json 
import numpy as np
import os

os.mkdir('web')
os.mkdir('web/assets')

css = """main{
    padding: 5%;
    margin: 0%;
    background-color: gray;
}

.Geral{
    gap: 1%;
}

.barras {
    display: flex;
    align-items: center;
    flex-direction: column;    
}

.barras__line1 {
    display: flex;
    justify-content: space-between;
    flex-direction: row;
    gap: 1.5rem;
    padding: 1.5rem;    
}
.barras__line2 {
    display: flex;
    align-items: center;
    flex-direction: row;    
     gap: 1.5rem;
    padding: 1.5rem;   
}

.pizza{
    display: flex;
    align-items: center;
    flex-direction: column;
    gap: 2rem;   
}

.imagem{
    border-style: solid;
    border-radius: 1.5%;
    border-color: gray;
}"""
html = """<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Bootstrap demo</title>
    <link rel="stylesheet" href="style.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
  </head>
  <body>
    <header></header>
    <main>
        <div class="Geral">    
            <div class="col-lg-12 barras">
                <div class="col-lg-12 barras__line1">
                    <img class="col-lg-6 imagem" src="assets/Figure_0.png" alt="">
                    <img class="col-lg-6 imagem" src="assets/Figure_1.png" alt="">
                </div>
                <div class="col-lg-12 barras__line2">
                    <img class="col-lg-6 imagem" src="assets/Figure_2.png" alt="">
                    <img class="col-lg-6 imagem" src="assets/Figure_3.png" alt="">
                </div>
                <div class="col-lg-12 barras__line2">
                    <img class="col-lg-6 imagem" src="assets/Figure_7.png" alt="">
                    <img class="col-lg-6 imagem" src="assets/Figure_8.png" alt="">
                </div>
                <div>
                    
                </div>
            </div>
            <div class="pizza">
                <img class="col-lg-12 imagem" src="assets/Figure_5.png" alt="">
                <img class="col-lg-12 imagem" src="assets/Figure_4.png" alt="">
                <img class="col-lg-12 imagem" src="assets/Figure_12.png" alt="">
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



print('='*170)
delimitador = input('Digite o delimitador dos arquivos csv: ')


with open('config.json', 'r', encoding='utf-8') as arquivo:
    dados_do_json = json.load(arquivo)

print("\n--- Acessando os dados como um dicionário Python ---")

for i in range(len(dados_do_json)):
    arquivo_entrada = dados_do_json[i]['arquivo_entrada']
    coluna_x = dados_do_json[i]['coluna_x']
    coluna_y = dados_do_json[i]['coluna_y']
    titulo = dados_do_json[i]['titulo']
    tipo = dados_do_json[i]['tipo']

    df = pd.read_csv(arquivo_entrada, sep=delimitador , engine='python')

    print('='*170)
    print(f"Arquivo de entrada: {arquivo_entrada}")
    print(f"Coluna X: {coluna_x}")
    print(f"Coluna Y: {coluna_y}")
    print(f"Titulo: {titulo}")
    if(tipo == 2):
        fig, ax = plt.subplots(figsize=(16,6))
        ax.pie(df[coluna_y], labels=df[coluna_x], autopct=lambda v:f"{df[coluna_y].sum()*v/100:.3f}")
        ax.set_title(titulo, fontsize=15)
        plt.tight_layout()
        plt.savefig(f"web/assets/Figure_{i}.png")
    elif(tipo == 1):
        fig, ax = plt.subplots(figsize=(7,5))
        ax.bar(df[coluna_x], df[coluna_y])
        ax.set_title(titulo, fontsize=15)
        ax.set_xlabel(coluna_x, fontsize=15)
        ax.set_ylabel(coluna_y, fontsize=15)
        plt.setp(ax.get_xticklabels(), rotation=15, ha="right")
        plt.tight_layout()
        plt.savefig(f"web/assets/Figure_{i}.png", bbox_inches='tight')
    else:
        print('='*170)
        print('Opção incorreta')
        print('='*170)
