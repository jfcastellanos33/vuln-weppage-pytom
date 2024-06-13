# vuln-weppage-pytom
#use  a Common Web Vulnerabilities to Scan
import nmap

def scan_vulnerabilities(target):
    # Crear un escáner nmap
    nm = nmap.PortScanner()

    # Ejecutar el escaneo con scripts de vulnerabilidades
    print(f"Escaneando {target} en busca de vulnerabilidades...")
    nm.scan(hosts=target, arguments='-sS --script vuln')

    # Mostrar resultados
    for host in nm.all_hosts():
        print(f'\nHost: {host} ({nm[host].hostname()})')
        print(f'Estado: {nm[host].state()}')

        for proto in nm[host].all_protocols():
            print(f'Protocolo: {proto}')
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                port_info = nm[host][proto][port]
                print(f'Puerto: {port}\tEstado: {port_info["state"]}')
                if 'script' in port_info:
                    for script_name, output in port_info['script'].items():
                        print(f'\nScript: {script_name}\nResultado:\n{output}')

if __name__ == "__main__":
    target = input("Introduce la dirección IP o el nombre de dominio objetivo: ")
    scan_vulnerabilities(target)
