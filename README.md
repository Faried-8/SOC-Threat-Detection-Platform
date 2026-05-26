# SOC-Threat-Detection-Platform

Enterprise Network Traffic Analysis & Threat Detection System.

## Easy Start (Recommended)

You can launch the entire platform automatically by double-clicking the **`run-project.bat`** file located in the root directory.

This script will:
1. Start the FastAPI backend server on port 8000.
2. Wait a few seconds for the backend to initialize (including database connection and MITRE ATT&CK STIX2 data fetching).
3. Start the React frontend on port 3000.
4. Open both processes in separate command prompt windows.

Once both windows are running, open your browser and navigate to:
**http://localhost:3000**

You can log in with:
- **Username**: admin
- **Password**: admin123

## Manual Start

If you prefer to start the components manually:

### Backend
```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```powershell
cd frontend
npm install  # (First time only)
npm run dev
```