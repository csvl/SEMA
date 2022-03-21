#!/usr/bin/env python3
import matplotlib.pyplot as plt
import pandas as pd
import researchpy as rp


class Graph:
    def __init__(self):
        pass

    def run(self):
        plt.figure()
        ax = plt.axes()
        """
        x = np.linspace(0,10,1000)
        ax.plot(x,np.sin(x))
        plt.show()
        """

        df = pd.read_csv("../res/raw.csv")

        # print(stats.f_oneway(df['nodes'][df['z3']==30 and df['time']==600],df['nodes'][df['z3']==60 and df['time']==600]))
        print(rp.summary_cont(df["nodes"][df["time"] == 3600]))
        print(rp.summary_cont(df["nodes"][df["time"] == 3600].groupby(df["z3"])))
        df1 = df[df["time"] == 3600]
        data = [df1["nodes"][df1["z3"] == 30], df1["nodes"][df1["z3"] == 60]]
        # df1 = pd.DataFrame(data,columns=['30','60'])
        # df1.plot.box()
        ax.boxplot(data, labels=["30", "60"])
        plt.show()
