# **Log File Analyzer / Intrusion Detection System**  
## **Overview**  
This project is a Python-based log analysis tool designed to detect suspicious activities such as brute-force attacks, unauthorized access attempts, and abnormal system behavior from various log files.  
## **Features**  
- Automatic log type detection (SSH, Apache, Nginx, Syslog, Firewall)  
- IP address extraction  
- Detection of repeated failed login attempts  
- Identification of suspicious and potentially compromised IPs  
- Automated security report generation  
## **Technologies Used**  
- Python 3  
- Regular Expressions (Regex)  
- Linux Terminal  
- Argparse (CLI handling)  
## **Usage**  
### **Run with file:**  
python3 analyzer.py -f sample_logs/ssh.log  
### **Interactive mode:**  
python3 analyzer.py  
## **Sample Output**  
The tool generates a structured report:  
- Suspicious IP addresses  
- Compromised IP detection  
- Event statistics  
## **Screenshots**  
See /screenshots folder for:  
- Execution proof  
- Report output  
## **Purpose**  
This project simulates a Security Operations Center (SOC) log analysis tool for cybersecurity training and portfolio demonstration.  
## **📚 References**  
- Secrepo Log Dataset Repository  
   
