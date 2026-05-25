"""
WebSocket connection manager for real-time SOC updates
"""
import json
import logging
from typing import Dict, List, Set
from fastapi import WebSocket

logger = logging.getLogger("WSManager")


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.session_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str = None):
        await websocket.accept()
        self.active_connections.append(websocket)
        if session_id:
            if session_id not in self.session_connections:
                self.session_connections[session_id] = []
            self.session_connections[session_id].append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket, session_id: str = None):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if session_id and session_id in self.session_connections:
            if websocket in self.session_connections[session_id]:
                self.session_connections[session_id].remove(websocket)

    async def broadcast(self, message: dict):
        """Broadcast to all connected clients"""
        data = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)

    async def send_to_session(self, session_id: str, message: dict):
        """Send to all clients watching a specific analysis session"""
        if session_id not in self.session_connections:
            return
        data = json.dumps(message)
        disconnected = []
        for connection in self.session_connections[session_id]:
            try:
                await connection.send_text(data)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            if conn in self.session_connections[session_id]:
                self.session_connections[session_id].remove(conn)

    async def send_alert(self, alert: dict):
        await self.broadcast({"type": "new_alert", "data": alert})

    async def send_pipeline_update(self, session_id: str, stage: str, progress: int, message: str):
        await self.send_to_session(session_id, {
            "type": "pipeline_update",
            "session_id": session_id,
            "stage": stage,
            "progress": progress,
            "message": message,
        })

    async def send_ioc(self, ioc: dict):
        await self.broadcast({"type": "new_ioc", "data": ioc})

    async def send_stats_update(self, stats: dict):
        await self.broadcast({"type": "stats_update", "data": stats})


ws_manager = ConnectionManager()
