import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

print('='*170)
print('Mova o dataframe .csv para o mesmo nivel de diretório deste programa')
caminho = 'dataframes/Vulnerabilidades_por_OS.csv'
delimitador = ';' 
print('='*170)
df = pd.read_csv(caminho, sep=delimitador, engine='python')

fig, ax = plt.subplots(figsize=(6, 3), subplot_kw=dict(aspect="equal"))

def func(pct, allvals):
    absolute = int(np.round(pct/100.*np.sum(allvals)))
    return f"{pct:.1f}%\n{absolute:d}"


wedges, texts, autotexts = ax.pie(df['Quantia de vulnerabilidade'], autopct=lambda pct: func(pct, df['Quantia de vulnerabilidade']),
                                  textprops=dict(color="w"))

ax.legend(wedges, df['Sistema_Operacional'],
          title='Sistemas Operacionais',
          loc="center left",
          bbox_to_anchor=(1, 0, 0.5, 1))

plt.setp(autotexts, size=8, weight="bold")

ax.set_title("Vulnerabilidades por OS")

plt.show()