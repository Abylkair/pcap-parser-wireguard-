# Wireguard PCAP Parser

Wireguard PCAP Analyzer is a web application for analyzing PCAP files using Python, Flask, and JavaScript.

## Installation

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/Abylkair/pcap-parser-wireguard-.git
    ```

2. Install Python dependencies using `pip`:

    ```bash
    pip install -r requirements.txt
    ```

3. Install Nmap (required for the project to run):

    - On Debian/Ubuntu:

        ```bash
        sudo apt-get install nmap
        ```

    - On macOS using Homebrew:

        ```bash
        brew install nmap
        ```

    - On Windows, download and install from the [Nmap website](https://nmap.org/download.html).

## Usage

1. Navigate to the project directory:

    ```bash
    cd wireguard-pcap-analyzer
    ```

2. Run the Flask application:

    ```bash
    python app.py
    ```

3. Open your web browser and go to `http://127.0.0.1:5000/` to access the application.

## Features

- Upload PCAP files for analysis.
- View detailed information about each packet in the file.
- Highlight anomalies in packets, such as unusual flags.

## Directory Structure

- `app.py`: The main Flask application file containing route handlers.
- `static/`: Directory for static resources (JavaScript, CSS).
- `templates/`: Directory for HTML templates.
- `requirements.txt`: File listing Python dependencies.

## Dependencies

- Flask: Microframework for web development in Python.
- scapy: Library for packet manipulation in Python.

## Developers

- Abylkair Shaigaliyev: [GitHub Profile](https://github.com/abylkair)

