document.getElementById('upload-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    const formData = new FormData(this);
    const response = await fetch('/parse', {
        method: 'POST',
        body: formData
    });

    if (response.ok) {
        const data = await response.json();
        const table = document.getElementById('packet-table');
        const tableBody = table.querySelector('tbody');
        tableBody.innerHTML = ''; // Clear any existing rows

        if (data.packets) {
            data.packets.forEach(packet => {
                const row = document.createElement('tr');
                
                // Network Type
                row.innerHTML += `<td>${packet['Network Type']}</td>`;
                
                // Ethernet
                row.innerHTML += `<td>${packet.Ethernet.dst}</td>`;
                row.innerHTML += `<td>${packet.Ethernet.src}</td>`;
                
                if (packet.IP) {
                    // IP
                    row.innerHTML += `<td>${packet.IP.version}</td>`;
                    row.innerHTML += `<td>${packet.IP.ihl}</td>`;
                    row.innerHTML += `<td>${packet.IP.tos}</td>`;
                    row.innerHTML += `<td>${packet.IP.len}</td>`;
                    row.innerHTML += `<td>${packet.IP.id}</td>`;
                    row.innerHTML += `<td>${packet.IP.flags}</td>`;
                    row.innerHTML += `<td>${packet.IP.frag}</td>`;
                    row.innerHTML += `<td>${packet.IP.ttl}</td>`;
                    row.innerHTML += `<td>${packet.IP.proto}</td>`;
                    row.innerHTML += `<td>${packet.IP.chksum}</td>`;
                    row.innerHTML += `<td>${packet.IP.src}</td>`;
                    row.innerHTML += `<td>${packet.IP.dst}</td>`;
                } else {
                    // Empty IP columns if no IP data
                    for (let i = 0; i < 13; i++) {
                        row.innerHTML += `<td></td>`;
                    }
                }

                if (packet.TCP) {
                    // TCP
                    row.innerHTML += `<td>${packet.TCP.sport}</td>`;
                    row.innerHTML += `<td>${packet.TCP.dport}</td>`;
                    row.innerHTML += `<td>${packet.TCP.seq}</td>`;
                    row.innerHTML += `<td>${packet.TCP.ack}</td>`;
                    row.innerHTML += `<td>${packet.TCP.dataofs}</td>`;
                    row.innerHTML += `<td>${packet.TCP.reserved}</td>`;
                    row.innerHTML += `<td>${packet.TCP.flags}</td>`;
                    row.innerHTML += `<td>${packet.TCP.window}</td>`;
                    row.innerHTML += `<td>${packet.TCP.chksum}</td>`;
                    row.innerHTML += `<td>${packet.TCP.urgptr}</td>`;
                    row.innerHTML += `<td>${packet.TCP.options.map(opt => `${opt[0]}: ${opt[1]}`).join(', ')}</td>`;
                } else {
                    // Empty TCP columns if no TCP data
                    for (let i = 0; i < 12; i++) {
                        row.innerHTML += `<td></td>`;
                    }
                }

                tableBody.appendChild(row);
            });

            // Display attack summary
            const attackSummary = document.getElementById('attack-summary');
            attackSummary.innerHTML = `<h3>Attack Summary</h3>
                                       <table>
                                           <tr><th>Attack Type</th><th>Attackers</th></tr>
                                           <tr><td>Deauthentication Attack</td><td>${data.attacks['Deauth Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>ARP Spoofing</td><td>${data.attacks['ARP Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>Packet Sniffing</td><td>${data.attacks['Sniffing Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>Replay Attack</td><td>${data.attacks['Replay Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>Evil Twin</td><td>${data.attacks['Evil Twin Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>DNS Tunneling</td><td>${data.attacks['DNS Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>ICMP Flood</td><td>${data.attacks['ICMP Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                           <tr><td>Port Scanning</td><td>${data.attacks['Port Attackers'].join(', ') || 'Attack not detected'}</td></tr>
                                       </table>`;
            attackSummary.style.display = 'block';

            table.style.display = 'table';
        } else {
            // Handle error
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="26">Error: ${data.error}</td>`;
            tableBody.appendChild(row);
            table.style.display = 'table';
        }
    } else {
        console.error('Error uploading file:', response.statusText);
    }
});

document.getElementById('clear-table').addEventListener('click', function () {
    const tableBody = document.getElementById('packet-table').querySelector('tbody');
    tableBody.innerHTML = ''; // Clear all rows
    document.getElementById('attack-summary').style.display = 'none'; // Hide attack summary
    document.getElementById('packet-table').style.display = 'none'; // Hide the table
});

document.querySelector('input[type="file"]').addEventListener('change', function () {
    const fileName = this.files[0].name;
    document.getElementById('file-name').textContent = fileName;
});
