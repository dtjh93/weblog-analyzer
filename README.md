# weblog-analyzer

This repository contains code implementing a Apache web log analyzer.

It is done as part of a recruitment assessment for Horangi Cybersecurity.

This web log analyzer carries out detection of 4 different types of attacks:
  1) Cross Site Scripting (XSS) attacks
  2) File Inclusion attacks
  3) Web shells
  4) Denial of Service(DoS) attempts/attacks 
  
Final product of the analyzer would be 4 different files (xssDetections.txt, fileInclusionDetections.txt, webshellDetections.txt, dosDetections.txt) containing web log records from the tested apache web log that have been identified as potential attacks.


<u><b>Installation guide</u></b>

<i>Requirements: </i>
  1) Python v3.6
  
<i>Using the analyzer:</i>
  1) The weblog analyzer is implemented within a single python script. (webloganalyzer.py)
  2) Download the webloganalyzer.py.
  3) Place the web log file to be scanned and webloganalyzer.py into the same directory.
  4) Run the webloganalyzer.py on command line/command prompt. Specify the web log file to be analyzed by adding it as a command  line argument.
  
