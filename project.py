# Analiza statica a fisierelor executabile

import re 
import sys
import time
import requests
try:
    from ipaddress import ip_address as ipo
except ImportError:
    from ipaddr import IPAddress as ipo

# ---------------------------------------------------------------------------------------------
WINDOWS_DLL = "windows_dll.txt"

FILE_DATA_PATH = "./data/data_file5.txt"
#FILE_DATA_PATH = "data.txt"
FILE_LINES = 0

# Starea fisierului
# Presupunem: 
# 0 > Nu este virus
# 100 > Este virus
# Se va face o lista cu valorile  iar apoi se va calcula media
FILE_ISVIRUS = [0]

# Adrese URL Gasite
FILE_URLS = []

# Adrese IP Gasite
FILE_IPS = []

# Keywords found
FILE_KEYWORDS = []

# Fisiere DLL gasite
FILE_DLL = []

# Informatii suspecte
FILE_SUSPICIOUS = []
FILE_SUSPICIOUS_PATH = FILE_DATA_PATH + "_suspicious.txt"
# ---------------------------------------------------------------------------------------------

# Save all URL to global Variables
def SaveURL(urlAddress):
    global FILE_URLS
    for urlToSave in urlAddress:
        uFound = False
        for url in FILE_URLS:
            if (url == urlToSave):
                uFound = True
                break
        if (uFound == False): FILE_URLS.append(urlToSave)
    return 0

# Save all IP to global Variables
def SaveIP(ipAddress):
    global FILE_IPS
    for ipToSave in ipAddress:
        ipFound = False
        for ip in FILE_IPS:
            if (ip == ipToSave):
                ipFound = True
                break
        if (ipFound == False): FILE_IPS.append(ipToSave)
    return 0

# Save all Keywords to global Variables
def SaveKeywords(word):
    global FILE_KEYWORDS
    fFound = False
    for uniq in FILE_KEYWORDS:
        if (uniq == word):
            fFound = True
            break
    if (fFound == False): FILE_KEYWORDS.append(word)
    return 0

# Save all DLL to global Variables
def SaveDLL(dllName):
    global FILE_DLL
    fFound = False
    for uniq in FILE_DLL:
        if (uniq == dllName):
            fFound = True
            break
    if (fFound == False): FILE_DLL.append(dllName)
    return 0
    
# Save all Suspicious data to global Variables
def SaveSuspicious(tagName):
    global FILE_SUSPICIOUS
    fFound = False
    for uniq in FILE_SUSPICIOUS:
        if (uniq == tagName):
            fFound = True
            break
    if (fFound == False): FILE_SUSPICIOUS.append(tagName)
    return 0

def Calculator():
    global FILE_ISVIRUS

    # Adrese URL
    for key in FILE_URLS:
        FILE_ISVIRUS.append(50)

    # Adrese IP
    for key in FILE_IPS:
        FILE_ISVIRUS.append(80)

    # Fisiere DLL
    for key in FILE_DLL:
        if (key.upper().find("(Windows)".upper()) >= 0):
            FILE_ISVIRUS.append(25)
        else:
            FILE_ISVIRUS.append(75)

    # Cuvinte cheie
    for key in FILE_KEYWORDS:
        FILE_ISVIRUS.append(80)

    # Calcularea rezultatului final
    allSum = 0
    for key in FILE_ISVIRUS:
        allSum = allSum + key

    finalResult = allSum / len(FILE_ISVIRUS)

    return str(finalResult) + "%" +" - din " +str(len(FILE_ISVIRUS))+ " de valori inregistrate."

# Afiseaza toate informatiile colectate
def ShowObtainedData(startTime):
    print("")
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    print("Adresele URL gasite sunt: ")
    for url in FILE_URLS:
        print(" > " + str(url))       
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    print("Adresele IP gasite sunt: ")
    for ip in FILE_IPS:
        print(" > " + str(ip))       
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    print("Cuvintele cheie gasite sunt: ")
    for key in FILE_KEYWORDS:
        print(" > " + str(key))       
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    print("Fisierele DLL gasite: ")
    for key in FILE_DLL:
        print(" > " + str(key))       
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    print("Alte informatii utile: " + str(len(FILE_SUSPICIOUS)))
    if (len(FILE_SUSPICIOUS) > 0):
        f = open(FILE_SUSPICIOUS_PATH, "w")
        for key in FILE_SUSPICIOUS:
            f.write(key + "\n")
        f.close()
        print (" > File: " + str(FILE_SUSPICIOUS_PATH))
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")
    print(" Fisierul introdus contine: " +str(FILE_LINES)+ " de linii")
    print(" Timpul necesar pentru analiza: " +str(time.time() - startTime)+ "s")
    print(" Scor: " + str(Calculator()))
    print("- - - - - - - - - - - - - - - - - - - - - - - - - - - ")

# Cauta pe site-ul microsoft daca fisierul DLL este unul oficial
def SearchOnInternet(dllFile):
    state = False
    urlMicrosoft = "https://docs.microsoft.com/en-us/search/?terms=About DLL File: " + str(dllFile)
    try:
        data = requests.get(urlMicrosoft)
        # Verifica numarul de aparitii in pagina
        if (data.text.count(dllFile) > 2):
            state = True
    except:
        pass
        #print ("[SearchOnInternet]: Failed to get Web Content.")
        #print ("[SearchOnInternet]: Error received: " + str(ex))
    return state

# Cauta in fisierul generat cu DLLs daca fisierul DLL se regaseste
def SearchOnFile(dllFile):
    state = False
    fp = open(WINDOWS_DLL, "r")
    fileLines = fp.readlines()
    for line in fileLines:
        if (line.upper().find(dllFile.upper())):
            state = True
            break
    fp.close()
    return state

# Verifica daca linia contine un cuvant cheie
def VerifyKeywords(line):
    listKeyWords = ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_CONFIG", "HKEY_USERS", 
    "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT"]
    for key in listKeyWords:
        if (line.upper().find(key) >= 0):
            SaveKeywords(key)
    return 0

# Verifica daca linia contine URL Address
def VerifyContainURL(line):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, line)
    return [x[0] for x in url] 

# Verifica daca linia contine IP Address
def VerifyContainIP(line):
    ipTmpList = []
    for group in line.split(" "):
        try:
            ipo(group)
            ipTmpList.append(group)
        except:
           pass
            #print("%s is not an IP." % (arg,))
    return ipTmpList

# Verifica data textul dat este Adresa IP sau nu
def isIPAddress(text):
    try:
        ipo(text)
        return True
    except:
        return False

# Verifica data textul dat este Adresa url sau nu
def isWebAddress(text):
    result = VerifyContainURL(text)
    for url in result:
        if url == text:
            return True
    return False

# Verifica tipurile de extensii folosite
def VerifyExtension(line):
    for group in line.split(" "):
        # Verifica daca exista un fisier DLL
        if (group.upper().rfind(".dll".upper()) >= 0):
            dState = SearchOnFile(group)
            sState = " (Windows)"
            if dState == False:
                sState = " (Other)"
            SaveDLL(group + str(sState))
        elif (group.count(".") == 1):
            extension = group[group.find("."):]
            if (extension != "." and extension != group):
                SaveSuspicious(group)
        elif (group.count(".") >= 2 and group.count(".") < 5):
            extension = group[group.find("."):]
            if (extension != ".." and extension != group and isWebAddress(group) == False):
                SaveSuspicious(group)

# Verifica fiecare linie din fisierul de analizat
def VerifyLine(line):
    # Verifica daca exista adrese URL si salveaza-le
    urls = VerifyContainURL(line)
    if (len(urls) > 0):
        SaveURL(urls)

    # Verifica daca exista adrese IP si salveaza-le
    ips = VerifyContainIP(line)
    if (len(ips) > 0):
        SaveIP(ips)

    # Verifica daca exista cuinte cheie folosite 
    VerifyKeywords(line)

    # Verifica extensiile gasite
    VerifyExtension(line)

    return 0

# Open App
def StartVerifyData():
    global FILE_LINES
    startTime = time.time()
    try:
        # Read File
        fp = open(FILE_DATA_PATH, "r")
        fileLines = fp.readlines()

        # Extrage fiecare linie din fisier
        for line in fileLines:
            if (line != ""):
                # Start Verify Normal
                FILE_LINES = FILE_LINES + 1
                VerifyLine("".join(line.split())) 
                # Remove All Spaces and verify again
                newLine = line.replace(" ", "")
                newLine = newLine.replace("\n", "")
                newLine = newLine.replace(chr(0), "")
                VerifyLine("".join(newLine.split())) 
        fp.close()

        # Verifica daca fisierul contine date
        if (FILE_LINES == 0):
            print("[GetData]: Fisierul nu contine informatii.")
            return 0
        
        # Afiseaza rezultatele finale
        ShowObtainedData(startTime)
    except Exception as ex:
        print("[GetData]: Failed to extrat information.")
        print("[GetData]: Error received: " + str(ex))
    return 0

# ---------------------------------------------------------------------------------------------
# Start App
StartVerifyData()
