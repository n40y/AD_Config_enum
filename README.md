# AD_Config_enum
Auditing Active Directory configurations


==============================================
## Create a Python virtual environment
==============================================

------------------------------------------------
### Sur Linux
------------------------------------------------
```bash
$ python3 -m venv nomDuFichier

$ source nomDuFichier/bin/activate
```
------------------------------------------------
### Sur Windows
------------------------------------------------
```bash
$ python3 -m venv nomDuFichier

$ source \nomDuFichier\Scripts\activate
```

=============================================
## Install Dependencies
=============================================
```bash
$ pip install -r requirements.txt
```

============================================
## Run
============================================
```bash
$ python main.py -t 192.168.1.10 -u jdupont -p MonPass -d corp.local -o rapport.json
```

