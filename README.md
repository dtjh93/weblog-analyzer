# weblog-analyzer (User Guide)

</br>
This repository contains code implementing a Apache web log analyzer.

</br>
It is done as part of a recruitment assessment for Horangi Cybersecurity.

</br>
This web log analyzer carries out detection of 4 different types of attacks:
  1) Cross Site Scripting (XSS) attacks
  2) File Inclusion attacks
  3) Web shells
  4) Denial of Service(DoS) attempts/attacks 

</br>
Final product of the analyzer would be 4 different files (xssDetections.txt, fileInclusionDetections.txt, webshellDetections.txt, dosDetections.txt) containing web log records from the tested apache web log that have been identified as potential attacks.

</br>

## Installation guide

<i>Requirements: </i>
  1) Python v3.6
  
<i>Using the analyzer:</i>
  1) The weblog analyzer is implemented within a single python script. (webloganalyzer.py)
  2) Download webloganalyzer.py.
  3) Place the web log file to be scanned and webloganalyzer.py into the same directory.
  4) Run webloganalyzer.py on command line/command prompt. Specify the web log file to be analyzed by adding it as a command  line argument.
  

</br>
## Credits/Resource List
</br>
  1) https://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
  2) http://resources.infosecinstitute.com/file-inclusion-attacks/
  3) https://www.owasp.org/index.php/Testing_Directory_traversal/file_include_(OTG-AUTHZ-001)#Testing_Techniques
  4) https://www.acunetix.com/blog/articles/detection-prevention-introduction-web-shells-part-5/
  5) https://www.us-cert.gov/ncas/alerts/TA15-314A
  6) https://medium.com/devops-challenge/apache-log-parser-using-python-8080fbc41dda
  7) https://www.acunetix.com/websitesecurity/cross-site-scripting/
