import nmap

def run_scan(target):
    nm = nmap.PortScanner()
    
    print(f"[+] Scanning {target} ...")
    
    nm.scan(hosts=target, arguments='-sS -sV -O')
    
    return nm
