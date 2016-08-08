import matplotlib.pyplot as plt
import numpy as np
import argparse
import os
import sys
import random

parser = argparse.ArgumentParser(description='Plot some timeseries.')

parser.add_argument('--filename', type=str,
                    default="/home/lavanyaj/MoonGen/control-0-log.txt")
parser.add_argument('--dataName', type=str,
                    default="set_tx_rate")
parser.add_argument('--value', type=str,
                    default="rate")
parser.add_argument('--showDataNames', action="store_true")
parser.add_argument('--startTime', type=float, default=0)
parser.add_argument('--endTime', type=float, default=sys.maxint)
parser.add_argument('--groupBy', type=str, default=None)
parser.add_argument('--groupByFor', nargs='+', type=int, default=None)
args = parser.parse_args()

"""
example
python simplePlot.py --dataName flow_tx_rate_configured --value configured --groupBy flow --groupByFor 100 101 --startTime 6.70e6 --endTime 6.74e6

head -n 40 all_flows.txt | xargs -n 40 python simplePlot.py --dataName flow_tx_rate_configured --value configured --groupBy flow --groupByFor
"""

def show_datanames(filename):
    os.system("|".join([("cat %s"%filename),
                        "awk '{print $1\" \"$2;}'",
                        "sort -u"]))
    
    
def filter_lines_by(filename, f, key, val, groupBy, groupByFor,\
                    startTime, endTime):
    
    print("Getting timeseries for %s from lines that start with %s in file %s"\
          %(val, key, filename))
    
    ##print("Between %f and %f s" % (startTime, endTime))
    print("Only showing %s: %s"\
          %(groupBy, str(groupByFor)))

    for i, line in enumerate(f):
        if line.startswith(key):
            words = line.split()
            fmt = words[1]
            fmtTokens = fmt.split("_")
            groupByIndex = fmtTokens.index(groupBy)
            timeIndex = fmtTokens.index("time")
            valIndex = fmtTokens.index(val)
            groupByForStr = [str(v) for v in groupByFor]
            newWords = words[2:]
            timeVal = float(newWords[timeIndex])
            # print "Is %s in %s? %s"%\
            #             (newWords[groupByIndex],\
            #              groupByForStr,\
            #              str(newWords[groupByIndex] in groupByForStr))
            
            if (timeVal >= startTime and timeVal <= endTime):
                if newWords[groupByIndex] in groupByForStr:
                    yield  newWords[groupByIndex] + " " + \
                        newWords[timeIndex] + " " + newWords [valIndex]
                
def filter_lines(filename, f, key, val, startTime, endTime):
    print("Getting timeseries for %s from lines that start with %s in %s"\
          %(val, key, filename))
    for i, line in enumerate(f):
        if line.startswith(key):
            words = line.split()
            fmt = words[1]
            fmtTokens = fmt.split("_")
            timeIndex = fmtTokens.index("time")
            valIndex = fmtTokens.index(val)
            newWords = words[2:]
            timeVal = float(newWords[timeIndex])
            if (timeVal >= startTime and timeVal <= endTime):
                yield  newWords[timeIndex] + " " + newWords[valIndex]
                
with open(args.filename) as f:
    # dataName = "set_flow_tx_rate"
    # groupBy = "100"
    # value = "rate"
    # data = np.genfromtxt(filter_lines_by(f, dataName, groupBy, value),
    #                      dtype='f')

    if args.showDataNames:
        show_datanames(args.filename)
    else:

        if  args.groupBy == None:
            data = np.genfromtxt(\
                                 filter_lines(\
                                              args.filename,\
                                              f,\
                                              args.dataName,\
                                              args.value,\
                                              args.startTime,\
                                              args.endTime),
                                 dtype='f')
            print data[2:,:]
            print data.shape
            
            outputFileName =\
                             "/home/lavanyaj/www/%s-%s_timeseries.pdf"\
                             %(args.dataName, args.value)

            plt.scatter(data[2:,0], data[2:,1])
            plt.show()
            plt.savefig(outputFileName)
        else:
            data = np.genfromtxt(\
                                 filter_lines_by(\
                                                 args.filename,\
                                                 f,\
                                                 args.dataName,\
                                                 args.value,\
                                                 args.groupBy,\
                                                 args.groupByFor,\
                                                 args.startTime,\
                                                 args.endTime),
                                 dtype='f')
            groupByForStr = "_".join([str(v) for v in args.groupByFor])
            if len(groupByForStr) > 15:
                groupByForStr = groupByForStr[:7] + "dotdotdot"+ groupByForStr[-7:]
                print groupByForStr

            outputFileName =\
                             "/home/lavanyaj/www/%s-%s_timeseries-%s_in_%s.pdf"\
                             %(args.dataName, args.value, args.groupBy, groupByForStr)

            print data
            print data.shape

            
            gb = data[:,0] # data[1:5, 0]
            # print "first five rows, flow no"
            # print gb
            
            plts = {}

            labelMarkers = {}
            arrLabelMarkers = []
            arrLabels = []

            i = 0
            for v in args.groupByFor:
                gbRows = gb==v
                # print "indices of rows where flow is %s" % (str(v))
                # print gbRows
                
                gbData = data[:,:][gbRows, :] # data[1:5,:][gbRows, :]
                # print "getting data where flow is %s" % (str(v))
                # print gbData

                col = plt.cm.jet(random.random()) 
                lab = "%s-%s"%(args.groupBy, str(v))
                plts[v] = plt.scatter(gbData[2:,1], gbData[2:,2],\
                                      c=col,
                                      label=lab)

                labelMarkers[v] = plt.Rectangle((0,0),1,1,fc=col)
                arrLabelMarkers.append(labelMarkers[v])

                arrLabels.append(lab)
                i = i + 1

            if len(arrLabels) < 16:
                plt.legend(tuple(arrLabelMarkers), tuple(arrLabels), loc='best')

            plt.savefig(outputFileName)
            #os.system("scp outputFileName lavanyaj@yuba.stanford.edu:~/public_html/percdemo/")

            #plt.scatter(data[2:,1], data[2:,2], c=data[2:,0], s=500)
            
            #plt.gray()
            #plt.savefig(outputFileName)
