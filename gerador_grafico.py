import matplotlib.pyplot as plt
import pandas as pd
import json 
import numpy as np

print('='*170)



with open('config.json', 'r', encoding='utf-8') as arquivo:
    dados_do_json = json.load(arquivo)

print("\n--- Acessando os dados como um dicionário Python ---")

for i in range(len(dados_do_json)):
    arquivo_entrada = dados_do_json[i]['arquivo_entrada']
    coluna_x = dados_do_json[i]['coluna_x']
    coluna_y = dados_do_json[i]['coluna_y']
    titulo = dados_do_json[i]['titulo']
    tipo = dados_do_json[i]['tipo']

    df = pd.read_csv(arquivo_entrada, sep=';' , engine='python')

    print('='*170)
    print(f"Arquivo de entrada: {arquivo_entrada}")
    print(f"Coluna X: {coluna_x}")
    print(f"Coluna Y: {coluna_y}")
    print(f"Titulo: {titulo}")
    if(tipo == 2):
        fig = plt.figure(figsize=(5,4))
        grafico = fig.add_axes([0,0,0.9,0.9])
        grafico.pie(df[coluna_y], labels=df[coluna_x], autopct=lambda v:f"{df[coluna_y].sum()*v/100:.3f}")
        grafico.set_title(titulo, fontsize=15)
        plt.show()
    elif(tipo == 1):
        fig = plt.figure(figsize=(7,5))
        bar = fig.add_axes([0.2,0.2,0.6,0.7])
        bar.bar(df[coluna_x], df[coluna_y])
        bar.set_title(titulo, fontsize=15)
        bar.set_xlabel(coluna_x, fontsize=15)
        bar.set_ylabel(coluna_y, fontsize=15)
        plt.show()
    else:
        print('='*170)
        print('Opção incorreta')
        print('='*170)
