from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import uvicorn
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import jwt
import redis
import json
import asyncio
import numpy as np
from typing import List, Dict, Optional
import tensorflow as tf
from sklearn.ensemble import IsolationForest
import cv2
import pandas as pd
import hashlib
import logging
from pydantic import BaseModel

# Configuración
DATABASE_URL = "postgresql://user:password@localhost/sidpa_db"
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"

# Base de datos
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis para cache y sesiones
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Modelos de Base de Datos
class ThreatDetection(Base):
    __tablename__ = "threat_detections"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String, index=True)
    severity = Column(String)
    confidence = Column(Float)
    source_ip = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    description = Column(Text)
    is_resolved = Column(Boolean, default=False)
    raw_data = Column(Text)

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(String, default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)

# Modelos Pydantic
class ThreatAlert(BaseModel):
    threat_type: str
    severity: str
    confidence: float
    source_ip: str
    description: str
    raw_data: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Optional[str] = "analyst"

# Crear tablas
Base.metadata.create_all(bind=engine)

# FastAPI app
app = FastAPI(
    title="SIDPA - Sistema Inteligente de Detección y Prevención de Amenazas",
    description="API para detección y prevención de amenazas cibernéticas",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Autenticación
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Clase para detección de amenazas
class ThreatDetector:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
    def train_model(self, data: np.ndarray):
        """Entrenar el modelo de detección de anomalías"""
        self.anomaly_detector.fit(data)
        self.is_trained = True
        logger.info("Modelo de detección entrenado exitosamente")
    
    def detect_network_anomaly(self, network_data: Dict) -> Dict:
        """Detectar anomalías en tráfico de red"""
        # Simular análisis de tráfico de red
        features = np.array([[
            network_data.get('packet_size', 0),
            network_data.get('connection_count', 0),
            network_data.get('bandwidth_usage', 0),
            network_data.get('port_scan_score', 0)
        ]])
        
        if self.is_trained:
            anomaly_score = self.anomaly_detector.decision_function(features)[0]
            is_anomaly = self.anomaly_detector.predict(features)[0] == -1
        else:
            # Lógica básica si no está entrenado
            anomaly_score = -0.5 if network_data.get('packet_size', 0) > 1500 else 0.1
            is_anomaly = anomaly_score < 0
        
        severity = "HIGH" if anomaly_score < -0.6 else "MEDIUM" if anomaly_score < -0.3 else "LOW"
        
        return {
            "is_threat": is_anomaly,
            "confidence": abs(anomaly_score),
            "severity": severity,
            "threat_type": "network_anomaly"
        }
    
    def detect_malware(self, file_hash: str, file_size: int) -> Dict:
        """Detectar malware basado en hashes conocidos"""
        # Lista simple de hashes maliciosos (en producción sería una base de datos)
        known_malware = {
            "d41d8cd98f00b204e9800998ecf8427e",  # Hash ejemplo
            "5d41402abc4b2a76b9719d911017c592"
        }
        
        is_malware = file_hash.lower() in known_malware
        confidence = 0.95 if is_malware else 0.1
        
        # Análisis heurístico básico
        if file_size > 10000000:  # Archivos muy grandes
            confidence += 0.2
        
        return {
            "is_threat": is_malware or confidence > 0.7,
            "confidence": min(confidence, 1.0),
            "severity": "HIGH" if is_malware else "MEDIUM",
            "threat_type": "malware"
        }

# Instancia global del detector
threat_detector = ThreatDetector()

# Endpoints de API
@app.get("/")
async def root():
    return {"message": "SIDPA API v1.0 - Sistema Inteligente de Detección y Prevención de Amenazas"}

@app.post("/auth/login")
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    # En producción, verificar contra la base de datos con hash de contraseña
    if login_data.username == "admin" and login_data.password == "admin123":
        access_token = create_access_token(data={"sub": login_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

@app.get("/threats")
async def get_threats(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(get_db),
    current_user: str = Depends(verify_token)
):
    threats = db.query(ThreatDetection).offset(skip).limit(limit).all()
    return threats

@app.post("/threats/detect")
async def detect_threat(
    threat_data: Dict,
    db: Session = Depends(get_db),
    current_user: str = Depends(verify_token)
):
    detection_type = threat_data.get("type", "network")
    
    if detection_type == "network":
        result = threat_detector.detect_network_anomaly(threat_data)
    elif detection_type == "malware":
        result = threat_detector.detect_malware(
            threat_data.get("file_hash", ""),
            threat_data.get("file_size", 0)
        )
    else:
        raise HTTPException(status_code=400, detail="Tipo de detección no soportado")
    
    # Guardar detección si es una amenaza
    if result["is_threat"]:
        detection = ThreatDetection(
            threat_type=result["threat_type"],
            severity=result["severity"],
            confidence=result["confidence"],
            source_ip=threat_data.get("source_ip", "unknown"),
            description=f"Amenaza detectada: {result['threat_type']}",
            raw_data=json.dumps(threat_data)
        )
        db.add(detection)
        db.commit()
        
        # Enviar alerta a Redis para tiempo real
        alert_data = {
            "id": detection.id,
            "type": result["threat_type"],
            "severity": result["severity"],
            "timestamp": datetime.utcnow().isoformat(),
            "confidence": result["confidence"]
        }
        redis_client.publish("threat_alerts", json.dumps(alert_data))
    
    return result

@app.get("/threats/stats")
async def get_threat_stats(
    db: Session = Depends(get_db),
    current_user: str = Depends(verify_token)
):
    total_threats = db.query(ThreatDetection).count()
    high_severity = db.query(ThreatDetection).filter(ThreatDetection.severity == "HIGH").count()
    resolved = db.query(ThreatDetection).filter(ThreatDetection.is_resolved == True).count()
    
    # Threats por tipo
    threat_types = db.query(ThreatDetection.threat_type, 
                           db.func.count(ThreatDetection.id).label('count'))\
                    .group_by(ThreatDetection.threat_type).all()
    
    return {
        "total_threats": total_threats,
        "high_severity": high_severity,
        "resolved": resolved,
        "pending": total_threats - resolved,
        "threat_types": {t.threat_type: t.count for t in threat_types}
    }

@app.put("/threats/{threat_id}/resolve")
async def resolve_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(verify_token)
):
    threat = db.query(ThreatDetection).filter(ThreatDetection.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Amenaza no encontrada")
    
    threat.is_resolved = True
    db.commit()
    return {"message": "Amenaza resuelta exitosamente"}

@app.get("/alerts/stream")
async def stream_alerts():
    """Stream de alertas en tiempo real usando Server-Sent Events"""
    async def event_stream():
        pubsub = redis_client.pubsub()
        pubsub.subscribe("threat_alerts")
        
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield f"data: {message['data']}\n\n"
    
    return StreamingResponse(event_stream(), media_type="text/plain")

@app.post("/model/train")
async def train_detection_model(
    current_user: str = Depends(verify_token)
):
    # Generar datos de entrenamiento simulados
    # En producción, estos vendrían de logs reales
    training_data = np.random.normal(0, 1, (1000, 4))
    threat_detector.train_model(training_data)
    
    return {"message": "Modelo entrenado exitosamente"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "services": {
            "database": "connected",
            "redis": "connected" if redis_client.ping() else "disconnected",
            "model": "trained" if threat_detector.is_trained else "untrained"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)