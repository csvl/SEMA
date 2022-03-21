#!/usr/bin/env python3

import matplotlib.pyplot as plt
import csv
import pylab


class PlotResults:
    def __init__(self):
        pass

    def run(self):
        plt.figure()

        values_30 = {}
        values_60 = {}

        with open("../res/raw.csv") as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=",")
            count = 0

            for row in csv_reader:
                if count == 0:
                    pass
                elif row[2] != "600" or "autoit" in row[0]:
                    pass
                else:
                    if "30" in row[3]:
                        temp = row[0].split("_")[1]
                        if temp in values_30:
                            values_30[temp]["nodes"] = values_30[temp]["nodes"] + int(
                                row[5]
                            )
                            values_30[temp]["edges"] = values_30[temp]["edges"] + int(
                                row[6]
                            )
                            values_30[temp]["connected_comp"] = values_30[temp][
                                "connected_comp"
                            ] + int(row[8])
                            values_30[temp]["n"] = values_30[temp]["n"] + 1
                        else:
                            values_30[temp] = {
                                "nodes": int(row[5]),
                                "edges": int(row[6]),
                                "connected_comp": int(row[8]),
                                "n": 1,
                            }
                    else:
                        temp = row[0].split("_")[1]
                        if temp in values_60:
                            values_60[temp]["nodes"] = values_60[temp]["nodes"] + int(
                                row[5]
                            )
                            values_60[temp]["edges"] = values_60[temp]["edges"] + int(
                                row[6]
                            )
                            values_60[temp]["connected_comp"] = values_60[temp][
                                "connected_comp"
                            ] + int(row[8])
                            values_60[temp]["n"] = values_60[temp]["n"] + 1
                        else:
                            values_60[temp] = {
                                "nodes": int(row[5]),
                                "edges": int(row[6]),
                                "connected_comp": int(row[8]),
                                "n": 1,
                            }
                count = count + 1
            height = []
            names = []
            x = []
            i = 0
            # print(values_60)
            for label in values_30:
                names = names + [label + "_30"]
                height = height + [
                    values_30[label]["connected_comp"] / values_30[label]["n"]
                ]
                # print(height)
                x = x + [i]
                i = i + 1
                names = names + [label + "_60"]
                height = height + [
                    values_60[label]["connected_comp"] / values_60[label]["n"]
                ]
                x = x + [i]
                i = i + 1

            print(height)
            pylab.xticks(x, names, rotation=90)
            width = 0.5
            plt.bar(x, height, width, color="bluecorner")
            plt.show()
