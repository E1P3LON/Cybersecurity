from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime
import os

# Configuración de base de datos
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sidpa_user:sidpa_pass@localhost/sidpa_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelos de base de datos
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(20), default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relaciones
    threat_detections = relationship("ThreatDetection", back_populates="assigned_user")

class ThreatDetection(Base):
    __tablename__ = "threat_detections"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(50), index=True, nullable=False)
    severity = Column(String(10), index=True, nullable=False)  # HIGH, MEDIUM, LOW
    confidence = Column(Float, nullable=False)
    source_ip = Column(String(45))  # IPv6 compatible
    destination_ip = Column(String(45))
    port = Column(Integer)
    protocol = Column(String(10))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    description = Column(Text)
    is_resolved = Column(Boolean, default=False, index=True)
    raw_data = Column(Text)
    assigned_user_id = Column(Integer, ForeignKey("users.id"))
    resolution_notes = Column(Text)
    resolved_at = Column(DateTime)
    
    # Relaciones
    assigned_user = relationship("User", back_populates="threat_detections")

class NetworkTraffic(Base):
    __tablename__ = "network_traffic"
    
    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    packet_size = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    flags = Column(String(20))
    is_suspicious = Column(Boolean, default=False, index=True)

class MalwareSignature(Base):
    __tablename__ = "malware_signatures"
    
    id = Column(Integer, primary_key=True, index=True)
    hash_md5 = Column(String(32), unique=True, index=True)
    hash_sha1 = Column(String(40), unique=True, index=True)
    hash_sha256 = Column(String(64), unique=True, index=True)
    malware_name = Column(String(100))
    malware_family = Column(String(50))
    severity = Column(String(10))
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    source = Column(String(50))  # Fuente de la información (VirusTotal, etc.)

class SystemEvent(Base):
    __tablename__ = "system_events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), index=True)
    hostname = Column(String(100))
    process_name = Column(String(100))
    process_id = Column(Integer)
    user_name = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_data = Column(Text)
    is_suspicious = Column(Boolean, default=False, index=True)

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50), index=True)
    severity = Column(String(10), index=True)
    title = Column(String(200))
    message = Column(Text)
    source_component = Column(String(50))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(50))
    acknowledged_at = Column(DateTime)

class Configuration(Base):
    __tablename__ = "configuration"
    
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True)
    value = Column(Text)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Función para crear todas las tablas
def create_tables():
    Base.metadata.create_all(bind=engine)

# Función para obtener sesión de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Función para insertar datos iniciales
def insert_initial_data():
    db = SessionLocal()
    try:
        # Verificar si ya existen datos
        if db.query(User).count() == 0:
            # Usuario administrador por defecto
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            
            admin_user = User(
                username="admin",
                email="admin@sidpa.com",
                hashed_password=pwd_context.hash("admin123"),
                role="admin"
            )
            db.add(admin_user)
            
            # Configuraciones por defecto
            default_configs = [
                {
                    "key": "threat_detection_threshold",
                    "value": "0.7",
                    "description": "Umbral de confianza para detección de amenazas"
                },
                {
                    "key": "alert_email_enabled",
                    "value": "true",
                    "description": "Habilitar alertas por correo electrónico"
                },
                {
                    "key": "max_threats_per_page",
                    "value": "50",
                    "description": "Máximo número de amenazas por página"
                },
                {
                    "key": "auto_resolve_low_threats",
                    "value": "false",
                    "description": "Resolver automáticamente amenazas de severidad baja"
                }
            ]
            
            for config in default_configs:
                db_config = Configuration(**config)
                db.add(db_config)
            
            # Firmas de malware de ejemplo
            example_signatures = [
                {
                    "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "hash_sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "malware_name": "TestMalware",
                    "malware_family": "Trojan",
                    "severity": "HIGH",
                    "source": "Manual"
                }
            ]
            
            for signature in example_signatures:
                db_signature = MalwareSignature(**signature)
                db.add(db_signature)
            
            db.commit()
            print("Datos iniciales insertados correctamente")
        else:
            print("Los datos iniciales ya existen")
    except Exception as e:
        print(f"Error insertando datos iniciales: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_tables()
    insert_initial_data()