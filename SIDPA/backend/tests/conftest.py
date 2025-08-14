# tests/conftest.py
import pytest
import asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
import redis
from unittest.mock import MagicMock

# Importar la aplicación
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app.main import app
from backend.database import Base, get_db

# Base de datos de prueba
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_sidpa.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session")
def db_engine():
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def mock_redis():
    return MagicMock(spec=redis.Redis)

@pytest.fixture
def sample_threat_data():
    return {
        "type": "network",
        "packet_size": 1500,
        "connection_count": 100,
        "bandwidth_usage": 80,
        "port_scan_score": 30,
        "source_ip": "192.168.1.100"
    }

@pytest.fixture
def sample_malware_data():
    return {
        "type": "malware",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
        "file_size": 1024,
        "source_ip": "10.0.0.50"
    }

@pytest.fixture
def auth_token(client):
    """Obtener token de autenticación para pruebas"""
    response = client.post("/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    return response.json()["access_token"]

# tests/test_auth.py
import pytest
from fastapi import status

def test_login_success(client):
    """Probar login exitoso"""
    response = client.post("/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_login_failure(client):
    """Probar login con credenciales incorrectas"""
    response = client.post("/auth/login", json={
        "username": "admin",
        "password": "wrongpassword"
    })
    
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Credenciales incorrectas" in response.json()["detail"]

def test_protected_endpoint_without_token(client):
    """Probar endpoint protegido sin token"""
    response = client.get("/threats")
    assert response.status_code == status.HTTP_403_FORBIDDEN

def test_protected_endpoint_with_token(client, auth_token):
    """Probar endpoint protegido con token válido"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/threats", headers=headers)
    assert response.status_code == status.HTTP_200_OK

# tests/test_threat_detection.py
import pytest
from unittest.mock import patch, MagicMock

def test_network_threat_detection(client, auth_token, sample_threat_data):
    """Probar detección de amenazas de red"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    response = client.post("/threats/detect", 
                          json=sample_threat_data, 
                          headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    
    assert "is_threat" in data
    assert "confidence" in data
    assert "severity" in data
    assert "threat_type" in data
    assert isinstance(data["confidence"], float)
    assert data["severity"] in ["LOW", "MEDIUM", "HIGH"]

def test_malware_threat_detection(client, auth_token, sample_malware_data):
    """Probar detección de malware"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    response = client.post("/threats/detect", 
                          json=sample_malware_data, 
                          headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    
    assert "is_threat" in data
    assert "confidence" in data
    assert data["threat_type"] == "malware"

def test_invalid_threat_type(client, auth_token):
    """Probar detección con tipo de amenaza inválido"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    invalid_data = {"type": "invalid_type"}
    
    response = client.post("/threats/detect", 
                          json=invalid_data, 
                          headers=headers)
    
    assert response.status_code == status.HTTP_400_BAD_REQUEST

@patch('backend.app.main.redis_client')
def test_threat_alert_redis_publish(mock_redis, client, auth_token):
    """Probar publicación de alertas en Redis"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    threat_data = {
        "type": "network",
        "packet_size": 3000,  # Valor alto para triggear amenaza
        "connection_count": 2000,
        "bandwidth_usage": 95,
        "port_scan_score": 80,
        "source_ip": "192.168.1.100"
    }
    
    mock_redis.publish = MagicMock()
    
    response = client.post("/threats/detect", 
                          json=threat_data, 
                          headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    
    # Verificar que se publicó en Redis si es amenaza
    if response.json().get("is_threat"):
        mock_redis.publish.assert_called_once()

# tests/test_threat_analyzer.py
import pytest
import numpy as np
from backend.threat_analyzer import NetworkAnalyzer, MalwareAnalyzer, ComprehensiveThreatAnalyzer

class TestNetworkAnalyzer:
    
    def test_extract_features(self):
        """Probar extracción de características de red"""
        analyzer = NetworkAnalyzer()
        network_data = {
            "packet_size": 1500,
            "connection_count": 100,
            "bandwidth_usage": 80,
            "port_scan_score": 30
        }
        
        features = analyzer.extract_features(network_data)
        assert features.shape == (1, 6)  # 6 características esperadas
        assert features[0][0] == 1500  # packet_size
        assert features[0][1] == 100   # connection_count

    def test_heuristic_analysis(self):
        """Probar análisis heurístico"""
        analyzer = NetworkAnalyzer()
        
        # Datos normales
        normal_data = {
            "packet_size": 1000,
            "connection_count": 50,
            "bandwidth_usage": 60,
            "port_scan_score": 10
        }
        score = analyzer._heuristic_analysis(normal_data)
        assert score >= -0.5  # No debería ser muy negativo
        
        # Datos sospechosos
        suspicious_data = {
            "packet_size": 3000,
            "connection_count": 2000,
            "bandwidth_usage": 95,
            "port_scan_score": 80
        }
        score = analyzer._heuristic_analysis(suspicious_data)
        assert score < -0.5  # Debería ser negativo

    def test_training(self):
        """Probar entrenamiento del modelo"""
        analyzer = NetworkAnalyzer()
        
        # Datos de entrenamiento simulados
        training_data = []
        for i in range(100):
            data = {
                "packet_size": np.random.randint(64, 1500),
                "connection_count": np.random.randint(1, 1000),
                "bandwidth_usage": np.random.randint(1, 100),
                "port_scan_score": np.random.randint(0, 100)
            }
            training_data.append(data)
        
        result = analyzer.train(training_data)
        assert result == True
        assert analyzer.is_trained == True

class TestMalwareAnalyzer:
    
    def test_analyze_file_hash_known_malware(self):
        """Probar análisis de hash conocido"""
        analyzer = MalwareAnalyzer()
        analyzer.load_malware_signatures(["d41d8cd98f00b204e9800998ecf8427e"])
        
        result = analyzer.analyze_file_hash("d41d8cd98f00b204e9800998ecf8427e")
        
        assert result["is_threat"] == True
        assert result["confidence"] >= 0.9
        assert result["severity"] == "HIGH"
        assert result["threat_type"] == "known_malware"

    def test_analyze_file_hash_unknown(self):
        """Probar análisis de hash desconocido"""
        analyzer = MalwareAnalyzer()
        
        result = analyzer.analyze_file_hash("unknown_hash_12345")
        
        assert result["is_threat"] == False
        assert result["threat_type"] == "unknown_file"

    def test_static_analysis(self):
        """Probar análisis estático"""
        analyzer = MalwareAnalyzer()
        
        # Contenido sospechoso
        suspicious_content = b"MZ\x90\x00virus trojan payload"
        result = analyzer._static_analysis(suspicious_content, "malware.exe")
        
        assert result["score"] > 0.3
        assert result["details"]["pe_file"] == True
        assert "suspicious_strings" in result["details"]

    def test_pattern_analysis(self):
        """Probar análisis de patrones"""
        analyzer = MalwareAnalyzer()
        
        # Contenido con patrones sospechosos
        malicious_content = b"eval(base64_decode('malicious_code'))"
        result = analyzer._pattern_analysis(malicious_content)
        
        assert result["score"] > 0
        assert len(result["details"]["matched_patterns"]) > 0

    def test_entropy_analysis(self):
        """Probar análisis de entropía"""
        analyzer = MalwareAnalyzer()
        
        # Contenido con alta entropía (aleatorio)
        high_entropy_content = np.random.bytes(1000)
        result = analyzer._entropy_analysis(high_entropy_content)
        
        entropy = result["details"]["entropy"]
        assert 0 <= entropy <= 8  # Rango válido de entropía
        
        # Contenido con baja entropía (repetitivo)
        low_entropy_content = b"A" * 1000
        result = analyzer._entropy_analysis(low_entropy_content)
        
        assert result["details"]["entropy"] < 2  # Muy baja entropía

class TestComprehensiveThreatAnalyzer:
    
    @pytest.mark.asyncio
    async def test_analyze_comprehensive_network(self):
        """Probar análisis comprehensivo de red"""
        analyzer = ComprehensiveThreatAnalyzer()
        
        threat_data = {
            "type": "network",
            "packet_size": 2000,
            "connection_count": 1500,
            "bandwidth_usage": 95,
            "port_scan_score": 70,
            "source_ip": "192.168.1.100"
        }
        
        result = await analyzer.analyze_comprehensive(threat_data)
        
        assert "timestamp" in result
        assert "analyses" in result
        assert "final_assessment" in result
        assert "network" in result["analyses"]

    @pytest.mark.asyncio
    async def test_analyze_comprehensive_malware(self):
        """Probar análisis comprehensivo de malware"""
        analyzer = ComprehensiveThreatAnalyzer()
        analyzer.configure({
            "malware_signatures": ["d41d8cd98f00b204e9800998ecf8427e"]
        })
        
        threat_data = {
            "type": "file",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_size": 1024
        }
        
        result = await analyzer.analyze_comprehensive(threat_data)
        
        assert "analyses" in result
        assert "hash_analysis" in result["analyses"]
        assert result["analyses"]["hash_analysis"]["is_threat"] == True

    def test_generate_final_assessment(self):
        """Probar generación de evaluación final"""
        analyzer = ComprehensiveThreatAnalyzer()
        
        analyses = {
            "network": {
                "is_threat": True,
                "confidence": 0.8,
                "severity": "HIGH",
                "threat_type": "network_anomaly"
            },
            "malware": {
                "is_threat": False,
                "confidence": 0.2,
                "severity": "LOW", 
                "threat_type": "unknown_file"
            }
        }
        
        assessment = analyzer._generate_final_assessment(analyses)
        
        assert "is_threat" in assessment
        assert "confidence" in assessment
        assert "severity" in assessment
        assert assessment["is_threat"] == True  # Cualquier análisis positivo
        assert assessment["confidence"] == 0.8  # Max confidence
        assert assessment["severity"] == "HIGH"  # Max severity

# tests/test_api_endpoints.py
def test_get_threats_empty(client, auth_token):
    """Probar obtener amenazas cuando no hay ninguna"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/threats", headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []

def test_get_threat_stats_empty(client, auth_token):
    """Probar estadísticas cuando no hay amenazas"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.get("/threats/stats", headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    
    expected_keys = ["total_threats", "high_severity", "resolved", "pending", "threat_types"]
    for key in expected_keys:
        assert key in data
    assert data["total_threats"] == 0

def test_resolve_nonexistent_threat(client, auth_token):
    """Probar resolver amenaza que no existe"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.put("/threats/999/resolve", headers=headers)
    
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "no encontrada" in response.json()["detail"]

def test_train_model(client, auth_token):
    """Probar entrenamiento de modelo"""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = client.post("/model/train", headers=headers)
    
    assert response.status_code == status.HTTP_200_OK
    assert "entrenado exitosamente" in response.json()["message"]

def test_health_check(client):
    """Probar endpoint de salud"""
    response = client.get("/health")
    
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "version" in data
    assert "services" in data

# tests/test_database.py
def test_create_threat_detection(db_session):
    """Probar creación de detección de amenaza"""
    from backend.database import ThreatDetection
    
    threat = ThreatDetection(
        threat_type="network_anomaly",
        severity="HIGH",
        confidence=0.85,
        source_ip="192.168.1.100",
        description="Test threat"
    )
    
    db_session.add(threat)
    db_session.commit()
    
    # Verificar que se guardó
    saved_threat = db_session.query(ThreatDetection).first()
    assert saved_threat.threat_type == "network_anomaly"
    assert saved_threat.severity == "HIGH"
    assert saved_threat.confidence == 0.85

def test_user_creation(db_session):
    """Probar creación de usuario"""
    from backend.database import User
    
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="hashedpass123",
        role="analyst"
    )
    
    db_session.add(user)
    db_session.commit()
    
    # Verificar que se guardó
    saved_user = db_session.query(User).filter(User.username == "testuser").first()
    assert saved_user.username == "testuser"
    assert saved_user.email == "test@example.com"
    assert saved_user.role == "analyst"

# tests/test_integration.py
@pytest.mark.integration
class TestIntegration:
    """Pruebas de integración que requieren servicios externos"""
    
    def test_full_threat_detection_flow(self, client, auth_token):
        """Probar flujo completo de detección de amenazas"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        # 1. Detectar amenaza
        threat_data = {
            "type": "network",
            "packet_size": 3000,
            "connection_count": 2000,
            "bandwidth_usage": 95,
            "port_scan_score": 80,
            "source_ip": "192.168.1.100"
        }
        
        detect_response = client.post("/threats/detect", 
                                    json=threat_data, 
                                    headers=headers)
        assert detect_response.status_code == status.HTTP_200_OK
        
        # 2. Obtener amenazas
        threats_response = client.get("/threats", headers=headers)
        assert threats_response.status_code == status.HTTP_200_OK
        threats = threats_response.json()
        
        if detect_response.json().get("is_threat"):
            assert len(threats) > 0
            threat_id = threats[0]["id"]
            
            # 3. Resolver amenaza
            resolve_response = client.put(f"/threats/{threat_id}/resolve", 
                                        headers=headers)
            assert resolve_response.status_code == status.HTTP_200_OK
            
            # 4. Verificar estadísticas
            stats_response = client.get("/threats/stats", headers=headers)
            stats = stats_response.json()
            assert stats["resolved"] >= 1

# tests/test_performance.py
import time
import pytest

@pytest.mark.performance
class TestPerformance:
    """Pruebas de rendimiento"""
    
    def test_threat_detection_performance(self, client, auth_token):
        """Probar rendimiento de detección de amenazas"""
        headers = {"Authorization": f"Bearer {auth_token}"}
        threat_data = {
            "type": "network",
            "packet_size": 1500,
            "connection_count": 100,
            "bandwidth_usage": 80,
            "port_scan_score": 30,
            "source_ip": "192.168.1.100"
        }
        
        # Medir tiempo de respuesta
        start_time = time.time()
        
        response = client.post("/threats/detect", 
                             json=threat_data, 
                             headers=headers)
        
        end_time = time.time()
        response_time = end_time - start_time
        
        assert response.status_code == status.HTTP_200_OK
        assert response_time < 2.0  # Menos de 2 segundos
    
    def test_concurrent_threat_detection(self, client, auth_token):
        """Probar detección concurrente de amenazas"""
        import threading
        import queue
        
        headers = {"Authorization": f"Bearer {auth_token}"}
        threat_data = {
            "type": "network",
            "packet_size": 1500,
            "connection_count": 100,
            "bandwidth_usage": 80,
            "port_scan_score": 30,
            "source_ip": "192.168.1.100"
        }
        
        results = queue.Queue()
        
        def make_request():
            try:
                response = client.post("/threats/detect", 
                                     json=threat_data, 
                                     headers=headers)
                results.put(response.status_code)
            except Exception as e:
                results.put(f"Error: {e}")
        
        # Crear 10 threads concurrentes
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Esperar que terminen todos
        for thread in threads:
            thread.join()
        
        # Verificar resultados
        success_count = 0
        while not results.empty():
            result = results.get()
            if result == 200:
                success_count += 1
        
        assert success_count >= 8  # Al menos 8 de 10 exitosas

# pytest.ini
[pytest]
markers =
    integration: marks tests as integration tests (deselect with '-m "not integration"')
    performance: marks tests as performance tests (deselect with '-m "not performance"')
    slow: marks tests as slow (deselect with '-m "not slow"')

testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Para ejecutar las pruebas:
# pytest                              # Todas las pruebas
# pytest -m "not integration"         # Sin pruebas de integración
# pytest -m "not performance"         # Sin pruebas de rendimiento
# pytest -v                          # Verbose
# pytest --cov=backend               # Con cobertura de código
# pytest tests/test_auth.py          # Solo pruebas de autenticación