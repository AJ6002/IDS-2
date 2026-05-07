import pandas as pd
df=pd.read_csv('combine.csv')
print(df[' Label'].value_counts())
