from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from generate_threat_map import run_update
import os
import csv
import io
import datetime
from contextlib import asynccontextmanager

# Global variable to store the latest data
cached_data = {
    "threats": None,
    "svg": None,
    "history": [] # Stores {time, count}
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initial data load on startup
    print("Initializing threat data...")
    try:
        threats, svg = run_update()
        if threats:
            cached_data["threats"] = threats
            cached_data["svg"] = svg
        else:
            print("Warning: run_update returned no data. Using empty defaults.")
            cached_data["threats"] = { "North America": [], "Europe": [], "Asia": [], "South America": [], "Africa": [], "Oceania": [] }
    except Exception as e:
        print(f"CRITICAL ERROR during startup: {e}")
        cached_data["threats"] = { "North America": [], "Europe": [], "Asia": [], "South America": [], "Africa": [], "Oceania": [] }
    
    # Record initial history
    count = 0
    if cached_data["threats"]:
        for continent in cached_data["threats"]:
            count += len(cached_data["threats"][continent])
    
    cached_data["history"].append({
        "time": datetime.datetime.now().strftime("%H:%M"),
        "count": count
    })
    yield

app = FastAPI(
    title="Live Threat Map API",
    description="API to fetch live threat data and generated maps",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return FileResponse("index.html")

@app.get("/threats")
async def get_threats():
    """Returns the latest threat data in JSON format"""
    if cached_data["threats"] is None:
        return {"error": "Data not available yet"}
    return cached_data["threats"]

@app.get("/history")
async def get_history():
    """Returns the history of threat counts for the chart"""
    return cached_data["history"]

@app.get("/map")
async def get_map():
    """Returns the generated SVG map"""
    if cached_data["svg"] is None:
        # Check if file exists on disk as fallback
        if os.path.exists("threat-map.svg"):
            with open("threat-map.svg", "r", encoding="utf-8") as f:
                cached_data["svg"] = f.read()
        else:
            return {"error": "SVG map not available yet"}
    
    return Response(content=cached_data["svg"], media_type="image/svg+xml")

@app.post("/refresh")
async def refresh_data():
    try:
        threats, svg = run_update()
        if threats:
            cached_data["threats"] = threats
            cached_data["svg"] = svg
            
            # Update history
            count = 0
            for continent in threats:
                count += len(threats[continent])
            
            cached_data["history"].append({
                "time": datetime.datetime.now().strftime("%H:%M"),
                "count": count
            })
            # Keep only last 20 records
            if len(cached_data["history"]) > 20:
                cached_data["history"].pop(0)
            
            return {"message": "Data refreshed successfully"}
        return {"error": "Refresh returned no data"}
    except Exception as e:
        return {"error": f"Refresh failed: {str(e)}"}

@app.get("/download-csv")
async def download_csv():
    """Generates and downloads a CSV of all current threat data"""
    if not cached_data["threats"]:
        return Response(content="No data available yet", status_code=503)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["IP", "Port", "CVE", "Country", "Continent", "Latitude", "Longitude",
                     "MAC Address", "Device Vendor", "Device Type", "Flags"])

    for continent, threats in cached_data["threats"].items():
        for t in threats:
            writer.writerow([
                t.get("ip", ""),
                t.get("port", ""),
                t.get("cve", ""),
                t.get("country", ""),
                t.get("continent", continent),
                t.get("lat", ""),
                t.get("lon", ""),
                t.get("mac_address", ""),
                t.get("device_vendor", ""),
                t.get("device_type", ""),
                " | ".join(t.get("flags", []))
            ])

    csv_bytes = output.getvalue().encode("utf-8-sig")  # utf-8-sig adds BOM for Excel compatibility
    filename = f"threat_export_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
