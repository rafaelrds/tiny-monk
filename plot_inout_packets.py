#!/usr/bin/env python
# a bar plot with errorbars
import numpy as np
import matplotlib.pyplot as plt

inout_grouped = {'social_in': 245, 'social_out': 248, 'news_out': 2169, 'institutional_in': 838, 'news_in': 2135, 'institutional_out': 855}



N = 3
in_traffic = (inout_grouped['social_in'], inout_grouped['news_in'], inout_grouped['institutional_in'])
out_traffic = (inout_grouped['social_out'], inout_grouped['news_out'], inout_grouped['institutional_out'])

ind = np.arange(N)  # the x locations for the groups
width = 0.35       # the width of the bars

fig, ax = plt.subplots()

rects2 = ax.barh(ind, out_traffic, width, color='#b37b9a')
rects1 = ax.barh(ind+width+0.018, in_traffic, width, color='#7bb394')

# add some text for labels, title and axes ticks
ax.set_xlabel('Packets')
ax.set_title('How many DNS packets went IN/OUT')
ax.set_yticks(ind+width)

ax.set_yticklabels( ('Social', 'News', 'Institutional') )

ax.legend( (rects1[0], rects2[0]), ('In', 'Out') )

def autolabel(rects):
    # attach some text labels
    for rect in rects:
        width = rect.get_width()
        print rect.get_width()
        ax.text(rect.get_x()+rect.get_width()+100, rect.get_y()+ rect.get_height()/2.0, '%d'%int(width),
		ha='center', va='center')

autolabel(rects1)
autolabel(rects2)

plt.xlim(0,2500)
plt.show()