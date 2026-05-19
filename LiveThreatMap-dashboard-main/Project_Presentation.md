# Live Threat Map Dashboard - Presentation (PPT Content)

*(Aap in slides ka text copy karke MS PowerPoint mein paste kar sakte hain. Slide ke hisaab se content divide kiya gaya hai.)*

---

## Slide 1: Title Slide
**Title:** ThreatVoyager - Live Cyber Defense Console
**Subtitle:** Real-time Global Cyber Threat Monitoring System
**Presented by:** [dharmveer kumar ram ]
**Roll Number / ID:** [MRT24PGMCA007]

---

## Slide 2: Introduction
**Heading:** What is ThreatVoyager?
* A dynamic, web-based cyber security dashboard.
* Designed to monitor and visualize cyber threats in real-time.
* Plots malicious IP addresses and targeted ports globally.
* Provides an intuitive graphical interface for security analysis.

---

## Slide 3: Why Do We Need It? (Problem Statement)
**Heading:** The Need for Visual Threat Intelligence
* **Invisible Threats:** Cyber attacks happen in the background and are hard to track using plain text logs.
* **Global Scale:** Attacks originate from all over the world, requiring geographic visualization.
* **Rapid Response:** Security teams need real-time data to identify trends (e.g., high-risk ports like 22 or 3389 being targeted).
* **Solution:** A centralized, live-updating map to instantly visualize the threat landscape.

---

## Slide 4: Key Features
**Heading:** Dashboard Capabilities
* **Interactive Threat Map:** Uses Leaflet.js to plot threat origins globally.
* **Live Shodan API Feed:** Pulls active threat data dynamically (with blocklist fallback).
* **Data Enrichment:** Automatically maps IPs to Countries, MAC Vendors, and Device Types.
* **Real-time Analytics:** Line chart showing threat intensity over time (Chart.js).
* **Export Functionality:** Analysts can download CSV reports for further study.
* **Thematic UI:** Modern, hacker-style glassmorphism design with themes.

---

## Slide 5: System Architecture
**Heading:** How It Works
1. **Data Polling:** Backend (Python/FastAPI) requests data from Shodan API or Public Blocklists.
2. **Geo-Location:** IPs are sent to `ip-api.com` to fetch Latitude and Longitude.
3. **API Endpoints:** FastAPI exposes `/threats`, `/history`, and `/map`.
4. **Frontend Render:** JavaScript fetches JSON data every 60 seconds and updates the map, side panel, and charts without reloading the page.

---

## Slide 6: Technologies Used
**Heading:** The Tech Stack
* **Frontend:**
  * HTML5, CSS3, Vanilla JavaScript
  * Leaflet.js (Map Rendering)
  * Chart.js (Data Visualization)
* **Backend:**
  * Python 3
  * FastAPI & Uvicorn (High-performance API)
  * Requests, Shodan Library, IPaddress
* **Data Sources:** Shodan API, IP-API, Spamhaus (Fallback)

---

## Slide 7: Project Screenshot (Dashboard UI)
*(Yahan par generated screenshot add karein jo chat mein diya gaya hai)*
**Heading:** Live Dashboard View
* [Insert Screenshot Here]
* **Map View:** Global attacks and red/green risk indicators.
* **Side Panel:** Live stream of incoming threats.
* **Analytics:** Intensity tracking graph.

---

## Slide 8: Future Enhancements
**Heading:** What's Next?
* **WebSocket Integration:** Moving from 60-second polling to instant real-time push updates.
* **Machine Learning:** Predicting future attack trends based on historical data.
* **Database Persistence:** Storing threat logs in a MongoDB/PostgreSQL database for long-term tracking.
* **Automated Blocking:** Integrating with firewall APIs to automatically block critical threats.

---

## Slide 9: Conclusion
**Heading:** Summary
* ThreatVoyager simplifies complex security logs into actionable visual intelligence.
* Successfully bridges powerful backend APIs with modern frontend frameworks.
* Lays a strong foundation for a scalable Security Information and Event Management (SIEM) tool.

---

## Slide 10: Q&A
**Heading:** Thank You!
* Questions? 
* (Provide contact info or GitHub link if needed)
