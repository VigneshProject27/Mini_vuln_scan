def parse_results(nm):
    results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():

                port_data = nm[host][proto][port]

                if port_data['state'] == 'open':
                    results.append({
                        "host": host,
                        "port": port,
                        "protocol": proto,
                        "service": port_data.get('name'),
                        "product": port_data.get('product'),
                        "version": port_data.get('version')
                    })

    return results
