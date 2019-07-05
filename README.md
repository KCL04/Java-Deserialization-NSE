# jd-scan
Wrote nse scripts for detecting Java Deserialization vulnerabilities using nmap

Just wrote the scripts, did not come up with vuln detection

Credit for JBoss.nse, Jenkins.nse vuln detection goes to Johndekroon

see: https://github.com/johndekroon/serializekiller

# Usage

Copy .nse scripts to /usr/share/nmap/scripts/ folder or the scripts folder where your nmap is installed

run: nmap -sV --script [script name] [target]
