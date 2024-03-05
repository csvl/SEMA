#!/usr/bin/env python3
import csv
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score,recall_score
#new = open('new.csv', mode='w')
#writer = csv.writer(new, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
y_true = []
y_pred = []
fam = [ 'Sodinokibi', 'simbot', 'RedLineStealer', 'FeakerStealer', 'gandcrab', 'lamer', 'nitol', 'RemcosRAT', 'sillyp2p', 'sfone', 'bancteian', 'ircbot', 'sytro','delf', 'wabot', 'none'] 
"""with open('outCDFS2.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            line_count += 1
            #writer.writerow(row)
        else:
            if row[2] in ['shiz','autoit']:
                families = eval(row[4])
                res = eval(row[5])
                max_s = 1
                for i in range(len(families)):
                    if i in [0,10]:
                        pass
                    else:
                        if res[max_s] < res[i]:
                            max_s = i
                row[2] = families[max_s]
                #writer.writerow(row)
            else:
                #writer.writerow(row)
            line_count += 1"""

with open('outBFS2.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count == 0:
            line_count += 1
            #writer.writerow(row)
        else:
            y_pred = y_pred + [fam.index(row[2])]
            y_true = y_true +[fam.index(row[1])] 
              

            line_count += 1

y_pred = y_pred + [fam.index(row[2])]
y_true = y_true +[fam.index(row[1])] 
acc = accuracy_score(y_true,y_pred)   
prc = precision_score(y_true,y_pred,average='macro') 
rec = recall_score(y_true,y_pred,average='macro')  

print("Accuracy is "+str(acc)) 
print("Precision is "+str(prc)) 
print("Recall is "+str(rec))    
            
conf = confusion_matrix(y_true,y_pred)
figsize = (10,7)
fontsize=9
df_cm = pd.DataFrame(conf, index=fam, columns=fam,)
fig = plt.figure(figsize=figsize)
try:
    heatmap = sns.heatmap(df_cm, annot=True, fmt="d",cbar=False)
except ValueError:
    raise ValueError("Confusion matrix values must be integers.")
heatmap.yaxis.set_ticklabels(heatmap.yaxis.get_ticklabels(), rotation=0, ha='right', fontsize=fontsize)
heatmap.xaxis.set_ticklabels(heatmap.xaxis.get_ticklabels(), rotation=45, ha='right', fontsize=fontsize)
plt.ylabel('True label')
plt.xlabel('Predicted label')
plt.show()
