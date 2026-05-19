# Project Report: Live Threat Map Dashboard (ThreatVoyager)

## 1. Project Title
**ThreatVoyager - Live Cyber Defense Console**

## 2. Abstract
In today's interconnected digital landscape, monitoring cyber threats in real-time is crucial for security analysts and organizations. The **Live Threat Map Dashboard** is a web-based application designed to fetch, analyze, and visualize global cyber threats dynamically. It provides an intuitive, map-based interface that plots malicious IP addresses, identifies targeted ports, and displays real-time statistics of inbound traffic.

## 3. Introduction
The objective of this project is to create a dynamic, visually engaging dashboard that makes it easy to understand complex cyber threat data. By leveraging open-source intelligence and security APIs (like Shodan), the application identifies potentially dangerous IP addresses worldwide and plots them on a global map. This tool helps in understanding attack vectors, origin countries, and the scale of potential threats.

## 4. Key Features
- **Real-Time Global Mapping:** Uses Leaflet.js to plot threat origins on an interactive dark-themed map.
- **Dynamic Threat Feeds:** Integrates with the Shodan API to pull active threats. Includes a fallback mechanism to public threat blocklists if the API rate limit is exceeded.
- **Data Enrichment:** Automatically maps IPs to their geographical locations, generates device vendor approximations, and classifies device types based on open ports.
- **Live Analytics:** Utilizes Chart.js to display a live-updating line chart of threat intensity over time.
- **CSV Data Export:** Allows security analysts to download the raw threat data (IP, Port, CVE, Location, etc.) directly as a CSV file for further analysis.
- **Thematic UI:** Offers multiple aesthetic themes (Vibrant Green, Deep Blue, Cyber Red, Matrix Mode) with a modern glassmorphism design.

## 5. Technologies Used
### Frontend (User Interface)
- **HTML5 & CSS3:** For structuring and styling the dashboard.
- **Vanilla JavaScript:** For frontend logic, API polling, and DOM manipulation.
- **Leaflet.js:** An open-source JavaScript library for mobile-friendly interactive maps.
- **Chart.js:** For rendering the threat intensity graph.

### Backend (Server & API)
- **Python 3:** Core programming language for data fetching and processing.
- **FastAPI:** A modern, high-performance web framework for building the backend API.
- **Uvicorn:** An ASGI web server implementation for Python to serve the FastAPI application.
- **Shodan Python Library:** For querying the Shodan search engine to find internet-connected devices and vulnerabilities.
- **Requests & IPaddress:** For handling HTTP requests to fallback APIs and parsing IP addresses.

## 6. System Architecture & Workflow
1. **Data Collection (`generate_threat_map.py`):** 
   - The system periodically polls the Shodan API using a specific query (e.g., `port:22,23,3389,80`).
   - If Shodan is unavailable, it queries public blocklists (e.g., Spamhaus, Abuse.ch).
2. **Data Enrichment:** 
   - Collected IPs are sent to a batch IP-Geolocation API (`ip-api.com`) to get Latitude, Longitude, and Country.
   - The backend computes mock MAC addresses and identifies potential hardware vendors and device types.
3. **API Endpoints (`main.py`):**
   - FastAPI serves the frontend HTML.
   - Exposes REST endpoints (`/threats`, `/history`, `/map`) that the frontend JavaScript calls every 60 seconds to get the latest data.
4. **Visualization (`index.html`):**
   - The frontend receives the JSON payload.
   - Updates the map markers, side-panel list, threat counters, and the live chart.

## 7. How to Run the Project
1. **Install Dependencies:**
   Ensure Python is installed, then run:
   ```bash
   pip install fastapi uvicorn requests shodan
   ```
2. **Set API Keys (Optional):**
   The project contains a default Shodan API key, but it can be overridden using environment variables.
3. **Start the Server:**
   Run the following command in the project directory:
   ```bash
   python main.py
   ```
4. **Access the Dashboard:**
   Open a web browser and navigate to: `http://localhost:8001`

## 8. Conclusion
The Live Threat Map Dashboard successfully demonstrates how to integrate third-party threat intelligence APIs with modern web frameworks. It bridges the gap between raw backend data and frontend visualization, providing a seamless and highly interactive user experience. This project serves as an excellent foundation for building more advanced Security Information and Event Management (SIEM) visualization tools.
