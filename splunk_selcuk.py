import io, os, sys, types, datetime, math, StringIO, time, glob
#import tables
from datetime import datetime, timedelta

import splunklib.client as client
import splunklib.results as results
import pandas as pd


#import numpy as np
#import xml.etree.cElementTree as et
#from collections import OrderedDict
#import csv

# Visualization
#import matplotlib.pyplot as plt
#%matplotlib inline
#import missingno
#import seaborn as sns

# Feature Selection and Encoding
#from sklearn.feature_selection import RFE
#from sklearn.decomposition import PCA
#from sklearn.preprocessing import OneHotEncoder, LabelEncoder

# Splunk configuration parameters
HOST = "10.210.149.190"
PORT = 8089
USERNAME = "splunk_username"
PASSWORD = "splunk_password"

# Splunk connection
service = client.connect(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD)
assert isinstance(service, client.Service)

# Function to Perform a Splunk search
def execute_query(searchquery_normal, 
                  kwargs_normalsearch={"exec_mode": "normal"}, 
                  kwargs_options={"output_mode": "csv", "count": 1000000}):
    # Execute Search
    job = service.jobs.create(searchquery_normal, **kwargs_normalsearch)

    # A normal search returns the job's SID right away, so we need to poll for completion
    while True:
        while not job.is_ready():
            pass
        stats = {"isDone": job["isDone"], "doneProgress": float(job["doneProgress"])*100, 
                 "scanCount": int(job["scanCount"]), "eventCount": int(job["eventCount"]), 
                 "resultCount": int(job["resultCount"])}
        status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   " 
                  "%(eventCount)d matched   %(resultCount)d results") % stats

        sys.stdout.write(status + '\n')
        sys.stdout.flush()
        if stats["isDone"] == "1":
            sys.stdout.write("\nDone!")
            break
        time.sleep(0.5)

    # Get the results and display them
    csv_results = job.results(**kwargs_options).read()
    job.cancel()
    return csv_results

# Function to split Splunk search queries by day, week or month
# This function helps you to search splunk without limiting 50000 search limit
# This function also creates .csv file to keep each queries output if it does not exist before.
# If the file exist not running splunk query 
def execute_query_bytime(search_query, filename, metric, last_day):
    for x in range(0,last_day):
        # Check if the search file is existing
        x_days_ago = datetime.now() - timedelta(days=x+1)
        timestr = x_days_ago.strftime("%Y_%m_%d")
        filename_new = filename + timestr + '.csv'
        print(filename_new)

        if file_exist(filename_new) == False:    
            #search_query_new = search_query + ' earliest=-' + str(x+1) + metric + ' latest=-' + str(x) + metric + parse_query
            search_query_new = search_query.replace("|",' earliest=-' + str(x+1) + metric + ' latest=-' + str(x) + metric + ' |',1)
            print('\n')
            print(search_query_new)

            csv_results = execute_query(search_query_new)

            for row in csv_results:
                if row[0] not in (None, ""):
                    df = pd.read_csv(StringIO.StringIO(csv_results), encoding='utf8', sep=',', low_memory=False)
                    df.to_csv(filename_new, sep=',', encoding='utf-8')
                    break
                break
    
# This function is to read csv file and return as panda dataframes
def read_csvs(filename):
    # Read all splunk files started with filename*.csv
    filenames = glob.glob(filename + "*.csv")
    
    frame = pd.DataFrame()
    list_ = []
    for file_ in filenames:
        df = pd.read_csv(file_,index_col=None, header=0)
        list_.append(df)
    frame = pd.concat(list_)
    frame.info()
    return(frame)

# This function checks if the given filename exist on project folder and return
def file_exist(filename):
    result=False
    #print(filename)
    if os.path.isfile(filename):
        result=True
    else:
        result=False
    print('Does CSV exist:' + str(result))
    return(result)

def disp_reader(rr):
    print('Display dictionary function has started')
    for result in rr:
        if isinstance(result, results.Message):
            # Diagnostic messages might be returned in the results
            print '%s: %s' % (result.type, result.message)
            print('Diagnostic')
        elif isinstance(result, dict):
            # Normal events are returned as dicts
            print result
            print('Normal')
    assert rr.is_preview == False

# Main Function
def main():
    print('Main function has started')

    # Searching for splunk sessions
    print('Searching for splunk sessions has started')
    filename='splunk_sessions'
    metric ='day@day'
    last_day = 10
    SEARCH_COMMAND = 'search index=decoder "M\=RepeatedPort C\=OVERLAY P\=RPStatusCheck\] printLog(): resMap" "crmModemStatus=found" \
    | rex field=_raw "(?i)(.*)(sessionIp=)(?<IPP>\d+\.\d+\.\d*)(.*)" \
    | dedup H,U,S,sessionIp \
    | table H,U,S,sessionIp,IPP,hdmModemStatus,hdmStatus,mediumType,nasPortId,pc,_time'
    execute_query_bytime(SEARCH_COMMAND, filename, metric, last_day)
    #df = read_csvs(filename)
    #df.to_pickle(filename)
    #store = HDFStore(filename+'.h5')
    #store['df'] = df  # save it

    # Searching splunk for tasks and requests
    print('Searching for tasks and requests has started')
    filename='splunk_requests'
    metric ='day@day'
    last_day = 10
    SEARCH_COMMAND = 'search index=decoder WF_CrmRequestAndNetflowTask results.properties \
    | table H,U,S,NetflowResultMsg1,NetflowResultMsg2,CrmRequestMsg2'
    execute_query_bytime(SEARCH_COMMAND, filename, metric, last_day)
    df = read_csvs(filename)
    df.to_pickle(filename)

    # Searching splunk for taskAciklamasi
    print('Searching for tasksAciklamasi')
    filename='splunk_taskAciklamasi'
    metric ='day@day'
    last_day = 10
    SEARCH_COMMAND = 'search index=decoder DESCRIPTIONDETAIL parametersMap "startStep=TASKBASLATMA" | rex "(\<COL.*NAME=.DESCRIPTIONDETAIL.\>\#\#.GLB\d{8}.\,.\d{2}.\d{2}.\d{4}.\d{2}?\:\d{2}?\:\d{2}?.\#\#.)(?P<TaskAciklama>(.*?)\.*#)([^\n]*\n+)+(.*)(\<COL.*NAME=.EMPTORREQUESTID.\>)(?P<EmptorRequestId>([1-9][0-9]*)?)([^\n]*\n+)+(.*)(\<COL.*NAME=.REQUESTLOGID.\>)(?P<RequestLogId>([1-9][0-9]*)?)" | table H,U,S, TaskAciklama, EmptorRequestId, RequestLogId'
    execute_query_bytime(SEARCH_COMMAND, filename, metric, last_day)
    df = read_csvs(filename)
    df.to_pickle(filename)

    #df = pd.read_csv(StringIO.StringIO(csv_results), encoding='utf8', sep=',', low_memory=False)
    #df.to_csv('splunk_selcuk_2017q3.csv', sep=',', encoding='utf-8')

if __name__ == "__main__":
    main()
