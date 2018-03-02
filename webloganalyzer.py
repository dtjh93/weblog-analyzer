import sys
import re
import os.path
import time
from collections import Counter


# checks if filename passed as command line argument exists
def fileIsValid(filename):
    if not os.path.isfile(filename):
        print("The file " + filename + " does not exist!")
        return 0
    else:
        return 1


# detect xss - #1
def createXSSDetectionsFile(filename):

    print ("detecting XSS attacks.. please wait...")
    with open(filename,'r') as log, open("xssDetections.txt", 'w') as xssDetections:

        # regex based on solutions proposed by https://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
        # r = raw string , /i= case insensitive

        # genericTags = regex that checks for < -anything- >. might detect alot false positives due to its safe nature
        genericTags = r"/(\%3C|<)[^\n]+((\%3E)|>)"

        # imgsrc = regex that checks for xss attacks using <img src= -> just check for <img -anything- > will be sufficient
        imgsrc = r"/((\%3C|<))(i|(\%69)|(\%49))(m|(\%4D)|(\%6D))(g|(\%47)|(\%67))[^\n]+((\%3E)|>)"

        # closingTags = regex that checks for any closing HTML formatting tag. Subset of genericTags,
        # but has lower chance of returning false positive as it additionally checks for '/' present in closing tags
        # - more likely of it being a HTML formatting tag/XSS attack.
        closingTags = r"/(\%3C|<)((\%2F)|/)[^\n]+((\%3E)|>)"

        # for each line in the log file, check if any of the warning signs (represented by regexs) of xss are present.
        # write line to xssDetections.txt as long as 1 warning sign present
        for line in log:
            genericTagsMatchFound = re.search(genericTags,line.lower())
            imgsrcMatchFound = re.search(imgsrc,line.lower())
            closingTagsFound = re.search(closingTags, line.lower())
            if genericTagsMatchFound is not None or imgsrcMatchFound is not None or closingTagsFound is not None:
                xssDetections.write(line)
    print ("XSS attack detection completed! [Output: xssDetections.txt]\n")


# detect file inclusion - #2
def createFileInclDetectionsFile(filename):

    print ("detecting File Inclusion attacks.. please wait...")
    with open(filename,'r') as log, open("fileInclusionDetections.txt", 'w') as fiDetections:

        # regex based on types of file inclusion attack documented by http://resources.infosecinstitute.com/file-inclusion-attacks/
        # and solutions suggested by https://www.owasp.org/index.php/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001)#Testing_Techniques

        # directoryTraversal = regex that checks for 1 or  more times of ../ or its hex equivalent. Used in local file inclusion attacks.
        directoryTraversal = r"((\.|\%2e)(\.|\%2e)(\\|\%5c|/|\%2f))+"

        # Special case - null byte terminator which allows any filetype to be accessed = regex checks for %00. Used in local file inclusion attacks.
        nullByteTerminator = r"\%(0|\%30)(0|\%30)"

        # check for file= or page= - occurence of these might signify the use of <include statements in code which
        # could make system susceptible to file inclusion attacks if no proper input validation mech in place. Used in both local and remote file inclusion attacks.
        fileOrPage = r"(f|\%66)(i|\%69)(l|\%6c)(e|\%65)(=|\%3d)|(p|\%70)(a|\%61)(g|\%67)(e|\%65)(=|\%3d)"

        # for each line in the log file, check if any of the warning signs (represented by regexs) of file inclusion are present.
        # write line to fileInclusionDetections.txt as long as 1 warning sign present
        for line in log:
            directoryTraversalFound = re.search(directoryTraversal,line.lower())
            nullByteTerminatorFound = re.search(nullByteTerminator,line.lower())
            fileOrPageFound = re.search(fileOrPage, line.lower())
            if directoryTraversalFound is not None or nullByteTerminatorFound is not None or fileOrPageFound is not None:
                fiDetections.write(line)
    print ("File inclusion attack detection completed! [Output: fileInclusionDetections.txt]\n")


# detect Web shells - #3
def createWebshellDetectionsFile(filename):

    print ("detecting potential webshells/webshell attacks.. please wait...")

    with open(filename,'r') as log, open("webshellDetections.txt", 'w') as wsDetections:

        # regex based on solutions suggested by https://www.acunetix.com/blog/articles/detection-prevention-introduction-web-shells-part-5/ &
        # https://www.us-cert.gov/ncas/alerts/TA15-314A

        # Detection method #1: search for common parameter names used by webshells -> file= / cmd=
        commonParameters = r"(f|\%66)(i|\%69)(l|\%6c)(e|\%65)(=|\%3d)|(c|\%63)(m|\%6d)(d|\%64)(=|\%3d)"

        # Detection method #2: search for common commands used by webshells
        # -> ls, cat<space> (might return a number of false positives, delete if happens) <commented out>
        #commonCommands = r"(c|\%63)(a|\%61)(t|\%74) "

        # Detection method #3: search for common known webshell names
        knownWebshells = r"(c99\.php|c100\.php|r57\.php|wso\.php|b374k\.php|caidao\.php|shell\.php|file\.php|weevely\.php|webshell\.php)"

        # Detection method #4: search for .php with long file names (>=70chars)
        # - long file names point to possible encoding of filename done by adversaries trying to evade detection
        encodedFilename = r"(/|=| )[^(\n|/|\\| )]{70,}(\.php|\.py|\.asp|\.pl|\.rb)"

        # Detection method #5: search for unexpected connections - parameters being passed to .jpg or .pdf file (search for .jpg? & .pdf?)
        unexpectedConnections = r"\.jpg\?|\.pdf\?"

        # for each line in the log file, check if any of the warning signs (represented by regexs) of webshells are present.
        # write line to webshellDetections.txt as long as 1 warning sign present
        for line in log:
            commonParametersFound = re.search(commonParameters,line.lower())
            #commonCommandsFound = re.search(commonCommands,line.lower())
            knownWebshellsFound = re.search(knownWebshells, line.lower())
            encodedFilenameFound = re.search(encodedFilename, line.lower())
            unexpectedConnectionsFound = re.search(unexpectedConnections, line.lower())
            if commonParametersFound is not None or knownWebshellsFound is not None or encodedFilenameFound is not None or unexpectedConnectionsFound is not None :
                wsDetections.write(line)

    print ("Webshell detection completed! [Output: webshellDetections.txt]\n")


# DoS detection - #4 additional interesting analysis strategies/techniques
def createDOSDetectionsFile(filename):

    print ("detecting potential DOS attacks.. please wait...")

    with open(filename,'r') as log, open("dosDetections.txt", 'w') as dosDetections:

        # Idea behind this detector is to go through the log file and identify instances where
        # a particular IP address has made more than 500 requests in a minute.
        # This high number of requests might signal an attempt of a DOS attack & should be investigated.

        # header for file
        dosDetections.write("Date       Time  IP-Address        Occurence\n")

        # regex for IP Address. taken from https://medium.com/devops-challenge/apache-log-parser-using-python-8080fbc41dda
        ipAddRegex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

        # timeAndIPList stores all date-time-ipAdd strings
        timeAndIPList = list()

        for line in log:

            # extract out time that line was recorded in the logs (in hours and minutes)/i.e. time when request was made
            timeInHrMins = line[0:16]

            # this block of code checks if line in log contains a client IP, if it does not, move on to next line in log
            if re.search(ipAddRegex,line[35:]) is not None:

                # find client IP using the regex
                ipAdd = re.search(ipAddRegex,line[35:]).group()

                # create the date-time-ipAdd string for line (e.g. 2015-11-05 04:00 67.213.222.143)
                timeAndIP =timeInHrMins + " " + ipAdd

                # add the date-time-ipAdd string into the timeAndIPList
                timeAndIPList.append(timeAndIP)

        # after iterating through all lines/records in the log file, count the occurences of each unique date-time-ipAdd string
        # the mapping of unique date-time-ipAdd string to its number of occurence will be represented by timeAndIPOccurenceMap
        timeAndIPOccurenceMap = Counter(timeAndIPList)

        # iterate through the timeAndIPOccurenceMap. If occurence for particular date-time-ipAdd string exceeds 500, write it to the dosDetections file.
        for key, value in timeAndIPOccurenceMap.items():
            if value > 500:
                dosDetections.write(key + "   -   " + str(value) + "\n")

    print ("DOS detection completed! [Output: dosDetections.txt]\n")


# take in command line argument (filename of log file)
filename = sys.argv[1]


# method that invokes all other methods that carry out detection of the various attacks.
if fileIsValid(filename):
    starttime = time.time()
    file = open(filename, 'r')
    print ("\n--- Analysis of " + filename + ": COMMENCING ---\n")
    createXSSDetectionsFile(filename)
    createFileInclDetectionsFile(filename)
    createWebshellDetectionsFile(filename)
    createDOSDetectionsFile(filename)
    print ("Time Taken: %s seconds\n--- Weblog Analysis : COMPLETED. ---" % (time.time()-starttime))
    file.close()
