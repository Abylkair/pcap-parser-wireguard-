document.getElementById('upload-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    const formData = new FormData(this);
    const response = await fetch('/parse', {
        method: 'POST',
        body: formData
    });

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
        table.style.display = 'table';
    } else {
        // Handle error
        const row = document.createElement('tr');
        row.innerHTML = `<td colspan="26">Error: ${data.error}</td>`;
        tableBody.appendChild(row);
        table.style.display = 'table';
    }
});

document.querySelector('input[type="file"]').addEventListener('change', function () {
    const fileName = this.files[0].name;
    document.getElementById('file-name').textContent = fileName;
});
