#!/usr/bin/env python3
from os import listdir
from os.path import isfile, join 
import json
import statistics as stat
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
sns.set('paper', style="whitegrid")
#sns.set('paper', style="white")

import IPython

DATA_LOC = "./data"
SAVE_LOC = "./graphs"

def load_json(data, path):
    with open(path, 'r') as f:
        for line in f:
            datum = json.loads(line)
            data.append(datum)
            #mtu = int(datum['mtu'])
            #if mtu in data.keys():
            #    data[mtu].append(datum)
            #else:
            #    data[mtu] = [datum]

def load_data():
    paths = [join(DATA_LOC,f) for f in listdir(DATA_LOC) if isfile(join(DATA_LOC,f))]

    data = []
    for path in paths:
        try:
            load_json(data, path)
        except FileNotFoundError:
            sys.stderr.write("Could not find {}\n".format(path))
        except json.decoder.JSONDecodeError:
            sys.stderr.write("Could not parse {}\n".format(path))

    return data

def analyze_data(ls):
    # calculate standard deviation
    stdev = stat.stdev(ls) 

    # take mean
    mean = stat.mean(ls) 

    return stdev, mean

# Seaborn does this for you when using Pandas :)
def process_data(data, mtu):
    # create lists
    aggr_data = {}
    for key in data[mtu][0].keys():
        aggr_data[key] = []

    # aggregate results
    for datum in data[mtu]:
        for key, value in datum.items():
            aggr_data[key].append(value)

    # remove bloat
    del aggr_data['datetime']
    del aggr_data['mtu']

    # analyze
    analyzed_data = {}
    for key, value in aggr_data.items():
        stdev, mean = analyze_data(value)
        analyzed_data[key] = round(mean, 1)
        analyzed_data['stdev_'+key] = round(stdev, 3)

        # calculate percentage success

    # recalculate percentage? seems ok

    return analyzed_data

# Based on Sharon Soussan
# https://stackoverflow.com/questions/43214978/seaborn-barplot-displaying-values
def show_values_on_bars(axs):
    def _show_on_single_plot(ax):        
        one_percent_graph = ax.get_ylim()[1] / 100

        for bar, line in zip(ax.patches, ax.lines):
            # center x bar
            _x = bar.get_x() + bar.get_width() / 2
            # just above stdev
            _y = line._y[1] + one_percent_graph

            if np.isnan(_y):
                # no stdev
                _y = bar.get_y() + bar.get_height() + one_percent_graph
            
            value = '{:.2f}'.format(bar.get_height())
            ax.text(_x, _y, value, ha="center", fontsize=8) 

    if isinstance(axs, np.ndarray):
        for idx, ax in np.ndenumerate(axs):
            _show_on_single_plot(ax)
    else:
        _show_on_single_plot(axs)

def create_graph(df):
    for ip in ['ipv4', 'ipv6']:
        mtu = 'mtu4' if ip == 'ipv4' else 'mtu6'

        mtus = df[mtu].unique()
        mtus.sort()
        mtus = mtus[::-1]

        for rslv in ['stub', 'rslv']:
            # colors
            #ax = sns.barplot(x='mtu', y=f'%failed_queries_{ip}_{rslv}',
            #                 data=df, order=mtus, ci='sd', errcolor="red",
            #                 palette=sns.color_palette("cubehelix"))

            ax = sns.barplot(x=mtu, y=f'%failed_queries_{ip}_{rslv}',
                             data=df, order=mtus, ci='sd', 
                             facecolor=(0.9295040369088812, 0.9295040369088812,
                                        0.9295040369088812),
                             errcolor="black", edgecolor="black")

            show_values_on_bars(ax)
            ax.set(xlabel='MTU size', ylabel='Percentage failed DNS UDP queries')

            plt.savefig(join(SAVE_LOC, f'{ip}_{rslv}.png'), format='png')
            plt.savefig(join(SAVE_LOC, f'{ip}_{rslv}.eps'), format='eps')
            #plt.show()
            #sys.exit(0)
            plt.close()

    #IPython.embed()

def main():
    data = load_data()
    df = pd.DataFrame(data)
    create_graph(df)

if __name__ == "__main__":
    main()
