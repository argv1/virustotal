# Virustotal
======================

## Purpose
Basic command line utility checking all files in provided folder using vt api v3

## Prerequisite

run pip to ensure all requirements are fulfilled
 
```bash
pip3 install -r requirements.txt
```

You also need virustotal.com api key, which you get [here](https://www.virustotal.com/gui/join-us) and store the credentials in the config.ini (or enter them at runtime)


## Usage
now you can run the script:
```bash
main.py -f FOLDER
```

## Future
There are plenty of more complex vt scripts out there, this was just a short implementation of api ver. 3
Feel free to improve and fork the script.

## License
This code is licensed under the [GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/). 
For more details, please take a look at the [LICENSE file](https://github.com/argv1/virustotal/blob/master/LICENSE).