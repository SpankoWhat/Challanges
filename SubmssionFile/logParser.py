from datetime import datetime
from genericpath import exists
import re
import os
import json

DEBUG = False
DOS_THRESHOLD = 100             #time in milliseconds
RAWFILENAME = "cleanLog"        #name of the cleaned log file
ANALYZEDFILE = "analysedlog"    #name of the analyzed json file
INPUTFILE = "inputFile.log"     #default input file
RESULTNAME = "results"          #name of results report


def main():
    global DEBUG
    global RAWFILENAME
    global ANALYZEDFILE
    global INPUTFILE
    global RESULTNAME

    handleUserInput()

    # check if file exists
    inputFile = open(INPUTFILE, "r")
    
    # Handles the bulk of cleaning and aqquiring the required data. This should be modified if 
    # more data is required
    cleanLog = parseLog(inputFile) 
    inputFile.close()
    ouput(cleanLog, RAWFILENAME, "log") # for debugging purposes

    # Handles the data processing and json formatting. Data processing should be added as necessary.
    jsonOutput = jsonFormater(cleanLog)
    ouput(jsonOutput, ANALYZEDFILE, "json") # raw data dump

    # Can be expanded to be a menu instead, where different analysis are built in...
    # though this is inefficient as all raw data is encoded in json anyway, apps like splunker or 
    # kibana can handle data analysis much better.
    analysesOutput = analyseDOS()
    ouput(analysesOutput, RESULTNAME, "txt") # raw data dump
    
def parseLog(input):
    global DEBUG
    cleanList = []
    nextLineCheck = False
    regexMatchOne = r'^\d+-\d+-\d+ \d+:\d+:\d+\.\d+\s+\D+-\D+.+[0-9].+Tx.+1{6}'
    regexMatchTwo = r'^\d+-\d+-\d+ \d+:\d+:\d+\.\d+\s+\D+-\D+.+[0-9].+Rx.+9{6}'

    # This logic assumes there will always be an answer...should account a fix for that
    for line in input:
        #alternates between two succesful regex matches
        if not nextLineCheck:
            lineObject = re.search(regexMatchOne, line)
        else:
            lineObject = re.search(regexMatchTwo, line)

        # Ignores the line if there is no match otherwise change flag
        if not lineObject:
            continue
        nextLineCheck = not nextLineCheck

        # adds the match to the list
        cleanList.append(lineObject[0].replace('\t',' '))

    return (formatHelper(cleanList)) # formats the data for easier analysis

def jsonFormater(input):
    global DOS_THRESHOLD
    regexMatch = r'(\d+-\d+-\d+ \d+:\d+:\d+\.\d+).+ ([0-9]+).+Tx.+1{6} (\d+-\d+-\d+ \d+:\d+:\d+\.\d+).+ [0-9]+.+Rx.+9{6}' #Removed fourth register
    
    ## This section does json formatting as well as injecting all data analyzed by dataAnalysis()
    analysisString = """{"DOS_THRESHOLD" : %s, "logs":[""" % (DOS_THRESHOLD)

    for tupleLine in re.findall(regexMatch, input):
        data = dataAnalysis(tupleLine[0], tupleLine[2]) # send data to be analyzed (more data can be sent as needed)
        analysisString +="""{"stream": "%s", "details":[{"start time": "%s" ,"end time" : "%s" ,"dos time" : "%ss", "dos attack" : "%s"}]},""" % (tupleLine[1], tupleLine[0], tupleLine[2], f"{data[0]:.2f}", data[1])
    
    analysisString += "]}"
    analysisString = ''.join(analysisString.rsplit(",",1)) # removes the last comma, there is porbs a better way.
    
    return analysisString

## This function handles all data gathering/analysis, if any optimization is required its here ;)
def dataAnalysis(*arguments):
    global DOS_THRESHOLD
    dos = False

    # Time is translated into a proper time format then is translated to epoch time for finer calculations
    timeOne = datetime.strptime(arguments[0], "%Y-%m-%d %H:%M:%S.%f").timestamp()
    timeTwo = datetime.strptime(arguments[1], "%Y-%m-%d %H:%M:%S.%f").timestamp()

    timeDiff =  timeTwo - timeOne
    if timeDiff > (DOS_THRESHOLD/1000): dos = True
    
    return (timeDiff, dos)

def analyseDOS():
    global ANALYZEDFILE
    alertList = ''
    jsonFileInput = open(ANALYZEDFILE+".json", "r")
    jsonObject = json.load(jsonFileInput)
    jsonFileInput.close()

    #Parses the json object
    alertList = "DOS_THRESHOLD: %sms\n" % (jsonObject["DOS_THRESHOLD"])
    for log in jsonObject["logs"]:
        if (log["details"][0]["dos attack"]) == "True":
            alertList += "DOS alert triggered -> Stream %s: %s\n" % (log["stream"], log["details"][0]["dos time"])

    return alertList

def ouput(input, name, format):
    fileName = name +"."+ format
    fullpath = os.getcwd() + "\\" + fileName

    if os.path.exists(fullpath):
        os.remove(fullpath)

    outputFile = open(fullpath, "x")
    outputFile.write(str(input))
    outputFile.close()

def formatHelper(input):
    textOuput = ''
    goNext = 0
    for line in input:
        if goNext == 2:
            textOuput +="\n"
            goNext = 0
        goNext += 1
        textOuput += line + " "
    return textOuput

def handleUserInput():
    global INPUTFILE
    global RAWFILENAME
    global ANALYZEDFILE
    global RESULTNAME

    fileExists = False
    projectName = input("Project Name: ")
    RAWFILENAME = projectName +"_"+ RAWFILENAME
    ANALYZEDFILE = projectName +"_"+ ANALYZEDFILE
    RESULTNAME = projectName +"_"+ RESULTNAME

    #USE TRY AND ACCEPT LOL LMAO

    while(not fileExists):
        inputFileName = input("Enter path of the log file (default=./inputFile.log): ")
        if len(inputFileName) > 0 and exists(inputFileName):
            INPUTFILE = inputFileName
            fileExists = not fileExists
        elif not len(inputFileName) > 0:
            fileExists = not fileExists
        else:
            print("Invalid file, try again ->")

#Start program
main()