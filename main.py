#!/usr/bin/env python3
'''
    Basic command line utility checking all files in provided folder using vt api v3
    
'''
import argparse
from configparser import ConfigParser
import datetime
import hashlib
import json
import logging
import os
import pandas as pd
from pathlib import Path
import requests
import time

# Define path and filename
base_path = Path(__file__).parent.absolute()
log_f = base_path / 'run.log'
config_f = base_path / 'config.ini'
url = 'https://www.virustotal.com/api/v3/files/'

def initialise_logger():
    # Setup Logging
    global logger 
    logger = logging.getLogger('vt_logger')
    logger.setLevel(logging.DEBUG)

    # create log file handler
    fh = logging.FileHandler(log_f)
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)

    # create stream handler (console output)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    # set format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)

    logger.info(f'Logger initialized. Log file {log_f} is being saved to {base_path}')

def get_credentials():
    # get credentials
    config_file = ConfigParser()
    config_file.read(config_f)
    settings = config_file['SETTINGS']
    credentials = {
        "apikey": "",
        "apitype": "",
        "scantype": ""
    }
    for entry in credentials:
        try:
            credentials[entry] = settings[entry]
        except KeyError:
            input(f'[?] VT {entry}: ') 

    return credentials

def scan_files(all_files, page_delay, apikey):   
    file_infos = []
    headers = {'x-apikey': apikey}
    logger.info(f'{len(all_files)} files in provided folder will be checked.')    

    for filename in all_files:
        # hash every file
        hash_sha256 = hashlib.sha256()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)                        

        tmp = { 
            "filename":             filename,
            "creation date":        datetime.date.fromtimestamp(filename.stat().st_ctime),
            "last modified date":   datetime.date.fromtimestamp(filename.stat().st_mtime),
            "sha265":               hash_sha256.hexdigest(),            
            "file_size":            convert_bytes(filename.stat().st_size)
            }

        # check vt with sha256 hash
        vt_url = url + hash_sha256.hexdigest()
        r = requests.get(vt_url, headers=headers)
        time.sleep(page_delay)

        if(r.status_code == 200):
            logger.info(f'File {filename} known to vt.')
            json_object = json.loads(r.text)
            tmp["community_vote"] = json_object["data"]["attributes"]["total_votes"]["harmless"] - json_object["data"]["attributes"]["total_votes"]["malicious"]
            tmp["scan_results"] = pd.Series([json_object["data"]["attributes"]["last_analysis_results"][entry]["category"] for entry in json_object["data"]["attributes"]["last_analysis_results"]]).value_counts()
            tmp["status"] = "File known"   
        elif(r.status_code == 404):
            logger.info(f'File {filename} unknown to vt.')
            if(filename.stat().st_size > 681600000):
                logger.info(f'File size of file {filename} exceeds the max. file size limit of 650 MiB')
                tmp["status"] = "Not uploaded, due to filesize"
            else:
                # upload function need to be implemented  
                logger.info(f'File {filename} could be uploaded to vt.')
            
        file_infos.append(tmp)

    return(pd.DataFrame(file_infos))
  
def convert_bytes(num):
    for unit in ['bytes', 'KiB', 'MiB', 'GiB', 'TiB']:
        if num < 1024.0:
            return f'{num} {unit}' if unit == 'bytes' else f'{num:.1f} {unit}'
        num /= 1024.0

def main():
    # Initiate the parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--folder', help='State the folder to be scanned', type=str, default=base_path)
    args = parser.parse_args()
  
    initialise_logger()
    credentials = get_credentials()
    # Time delay in seconds to wait for slow pages to load
    page_delay = 25 if credentials["apitype"] == "public" else 0
    logger.info(f'Request delay set to {page_delay}')

    all_files = list(Path(args.folder).rglob("*.*")) if(credentials["scantype"] == "strict") else list(Path(args.folder).glob("*.*"))
    if(len(all_files) > 500 and credentials["apitype"] == "public"):
        print(f"The number of files in the provided folder {args.folder} exceeds the daily limit of 500 files for Public API accounts.")
        raise SystemExit

    df = scan_files(all_files, page_delay, credentials["apikey"])
    pd.set_option("display.max_rows", None)
    print(df)

if __name__  == '__main__':
    main()