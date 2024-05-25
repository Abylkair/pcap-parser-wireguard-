# WireGuard

WireGuard is a web application designed to analyze network traffic captured in PCAP files. The application allows users to upload PCAP files, analyze the network packets within them, and detect various types of network attacks. WireGuard uses Flask for the backend, Scapy for packet analysis, and a simple frontend built with HTML, CSS, and JavaScript.

## Features

- **Upload PCAP Files**: Users can upload PCAP files to the application for analysis.
- **Detailed Packet Analysis**: The application parses the PCAP file and displays detailed information about each network packet.
- **Attack Detection**: WireGuard can detect and report several types of network attacks, including:
  - **Deauthentication Attack**: Identifies deauthentication packets and lists the MAC addresses involved.
  - **ARP Spoofing**: Detects ARP spoofing attempts and lists the MAC addresses of the attackers.
  - **Packet Sniffing**: Identifies potential sniffing activity based on broadcast traffic.
  - **Replay Attack**: Detects replay attacks by identifying duplicate packets with the same sequence and acknowledgment numbers.
  - **Evil Twin Attack**: Detects evil twin attacks by identifying duplicate SSIDs with different BSSIDs.
- **Attack Summary**: A mini-table at the top of the results displays a summary of detected attacks.
- **Clear Table**: A button to clear the table and attack summary.

## Updates

### Added Attack Detection

- **Deauthentication Attack**: Detects and lists MAC addresses involved in deauthentication attacks.
- **ARP Spoofing**: Detects ARP spoofing and lists MAC addresses of attackers.
- **Packet Sniffing**: Detects potential sniffing activity based on broadcast traffic and lists suspected attackers.
- **Replay Attack**: Detects replay attacks by checking for duplicate packets with the same sequence and acknowledgment numbers.
- **Evil Twin Attack**: Detects evil twin attacks by identifying duplicate SSIDs with different BSSIDs.

### Updated Frontend

- Added a button to clear the table and attack summary.
- Display attack summary in a mini-table format above the packet details.

### Updated Backend (`app.py`)

- Added functions to detect the above-mentioned attacks.
- Improved error handling and logging.

### Updated JavaScript (`scripts.js`)

- Added functionality to handle the "Clear Table" button.
- Updated the form submission to display detailed packet information and attack summaries.

## Usage

1. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2. **Run the Flask application**:
    ```bash
    python app.py
    ```

3. **Open your web browser** and navigate to `http://127.0.0.1:5000`.

4. **Upload a PCAP file** using the form.

5. **View the packet details and attack summary**.

6. **Clear the table and attack summary** by clicking the "Clear Table" button.

## File Structure

- `app.py`: The main Flask application file.
- `templates/index.html`: The main HTML file.
- `static/styles.css`: The CSS file for styling.
- `static/scripts.js`: The JavaScript file for frontend logic.
- `requirements.txt`: The list of dependencies.

## Dependencies

- Flask==2.0.3
- Scapy==2.4.5

## Author

- Shaigaliyev Abylkair
