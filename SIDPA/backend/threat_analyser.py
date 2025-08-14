import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
import cv2
import hashlib
import re
import requests
import json
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

class NetworkAnalyzer:
    """Analizador de tráfico de red para detectar anomalías"""
    
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_columns = [
            'packet_size', 'connection_count', 'bandwidth_usage',
            'port_scan_score', 'packet_frequency', 'protocol_diversity'
        ]
    
    def extract_features(self, network_data: Dict) -> np.ndarray:
        """Extraer características del tráfico de red"""
        features = []
        
        # Características básicas
        features.append(network_data.get('packet_size', 0))
        features.append(network_data.get('connection_count', 0))
        features.append(network_data.get('bandwidth_usage', 0))
        features.append(network_data.get('port_scan_score', 0))
        
        # Características calculadas
        packets = network_data.get('packets', [])
        if packets:
            # Frecuencia de paquetes
            time_diffs = [packets[i]['timestamp'] - packets[i-1]['timestamp'] 
                         for i in range(1, len(packets))]
            avg_frequency = np.mean(time_diffs) if time_diffs else 0
            features.append(avg_frequency)
            
            # Diversidad de protocolos
            protocols = set(p.get('protocol', 'unknown') for p in packets)
            protocol_diversity = len(protocols)
            features.append(protocol_diversity)
        else:
            features.extend([0, 0])
        
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data: List[Dict]):
        """Entrenar el modelo de detección de anomalías"""
        try:
            # Extraer características de los datos de entrenamiento
            features_list = []
            for data in training_data:
                features = self.extract_features(data)
                features_list.append(features.flatten())
            
            if not features_list:
                raise ValueError("No hay datos de entrenamiento")
            
            X = np.array(features_list)
            
            # Normalizar características
            X_scaled = self.scaler.fit_transform(X)
            
            # Entrenar modelo
            self.anomaly_detector.fit(X_scaled)
            self.is_trained = True
            
            logger.info(f"Modelo de red entrenado con {len(training_data)} muestras")
            return True
            
        except Exception as e:
            logger.error(f"Error entrenando modelo de red: {e}")
            return False
    
    def detect_anomaly(self, network_data: Dict) -> Dict:
        """Detectar anomalías en el tráfico de red"""
        try:
            features = self.extract_features(network_data)
            
            if self.is_trained:
                features_scaled = self.scaler.transform(features)
                anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
                is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
            else:
                # Análisis heurístico básico si no está entrenado
                anomaly_score = self._heuristic_analysis(network_data)
                is_anomaly = anomaly_score < -0.5
            
            confidence = min(abs(anomaly_score), 1.0)
            severity = self._calculate_severity(anomaly_score, network_data)
            
            return {
                'is_threat': is_anomaly,
                'confidence': confidence,
                'severity': severity,
                'threat_type': 'network_anomaly',
                'details': self._get_anomaly_details(network_data, anomaly_score)
            }
            
        except Exception as e:
            logger.error(f"Error en detección de anomalías de red: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'severity': 'LOW',
                'threat_type': 'network_anomaly',
                'details': {'error': str(e)}
            }
    
    def _heuristic_analysis(self, network_data: Dict) -> float:
        """Análisis heurístico cuando no hay modelo entrenado"""
        score = 0.0
        
        # Análisis de tamaño de paquete
        packet_size = network_data.get('packet_size', 0)
        if packet_size > 1500:  # MTU estándar
            score -= 0.3
        elif packet_size < 64:  # Paquetes muy pequeños
            score -= 0.2
        
        # Análisis de conexiones
        connections = network_data.get('connection_count', 0)
        if connections > 1000:  # Muchas conexiones simultáneas
            score -= 0.4
        
        # Análisis de ancho de banda
        bandwidth = network_data.get('bandwidth_usage', 0)
        if bandwidth > 90:  # Uso excesivo
            score -= 0.3
        
        # Port scanning detection
        port_scan_score = network_data.get('port_scan_score', 0)
        if port_scan_score > 50:
            score -= 0.5
        
        return score
    
    def _calculate_severity(self, anomaly_score: float, network_data: Dict) -> str:
        """Calcular severidad basada en el score y características"""
        if anomaly_score < -0.7:
            return 'HIGH'
        elif anomaly_score < -0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_anomaly_details(self, network_data: Dict, score: float) -> Dict:
        """Obtener detalles específicos de la anomalía"""
        details = {}
        
        if network_data.get('packet_size', 0) > 1500:
            details['large_packets'] = True
        
        if network_data.get('connection_count', 0) > 1000:
            details['excessive_connections'] = True
        
        if network_data.get('port_scan_score', 0) > 50:
            details['port_scanning'] = True
        
        details['anomaly_score'] = score
        return details

class MalwareAnalyzer:
    """Analizador de malware usando múltiples técnicas"""
    
    def __init__(self):
        self.known_signatures = set()
        self.suspicious_patterns = [
            r'eval\s*\(',  # Evaluación dinámica
            r'exec\s*\(',  # Ejecución dinámica
            r'system\s*\(',  # Llamadas al sistema
            r'shell_exec\s*\(',  # Ejecución de shell
            r'base64_decode\s*\(',  # Decodificación base64
            r'chr\s*\(\s*\d+\s*\)',  # Caracteres por código
            r'\\x[0-9a-fA-F]{2}',  # Códigos hexadecimales
        ]
        self.ml_model = None
        self.feature_extractor = None
    
    def load_malware_signatures(self, signatures: List[str]):
        """Cargar firmas conocidas de malware"""
        self.known_signatures.update(signatures)
        logger.info(f"Cargadas {len(signatures)} firmas de malware")
    
    def analyze_file_hash(self, file_hash: str) -> Dict:
        """Analizar archivo por hash"""
        file_hash = file_hash.lower().strip()
        
        # Verificar en firmas conocidas
        is_known_malware = file_hash in self.known_signatures
        
        if is_known_malware:
            return {
                'is_threat': True,
                'confidence': 0.95,
                'severity': 'HIGH',
                'threat_type': 'known_malware',
                'details': {'hash': file_hash, 'source': 'signature_database'}
            }
        
        return {
            'is_threat': False,
            'confidence': 0.1,
            'severity': 'LOW',
            'threat_type': 'unknown_file',
            'details': {'hash': file_hash}
        }
    
    def analyze_file_content(self, content: bytes, filename: str = "") -> Dict:
        """Analizar contenido del archivo"""
        try:
            # Análisis estático básico
            static_analysis = self._static_analysis(content, filename)
            
            # Análisis de patrones
            pattern_analysis = self._pattern_analysis(content)
            
            # Análisis de entropía
            entropy_analysis = self._entropy_analysis(content)
            
            # Combinar resultados
            threat_score = (
                static_analysis['score'] * 0.4 +
                pattern_analysis['score'] * 0.4 +
                entropy_analysis['score'] * 0.2
            )
            
            is_threat = threat_score > 0.6
            confidence = min(threat_score, 1.0)
            
            if threat_score > 0.8:
                severity = 'HIGH'
            elif threat_score > 0.5:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            details = {
                'static_analysis': static_analysis,
                'pattern_analysis': pattern_analysis,
                'entropy_analysis': entropy_analysis,
                'threat_score': threat_score
            }
            
            return {
                'is_threat': is_threat,
                'confidence': confidence,
                'severity': severity,
                'threat_type': 'file_analysis',
                'details': details
            }
            
        except Exception as e:
            logger.error(f"Error analizando contenido del archivo: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'severity': 'LOW',
                'threat_type': 'analysis_error',
                'details': {'error': str(e)}
            }
    
    def _static_analysis(self, content: bytes, filename: str) -> Dict:
        """Análisis estático del archivo"""
        score = 0.0
        details = {}
        
        # Análisis de extensión
        if filename:
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js']
            if any(filename.lower().endswith(ext) for ext in suspicious_extensions):
                score += 0.3
                details['suspicious_extension'] = True
        
        # Análisis de tamaño
        file_size = len(content)
        if file_size < 100:  # Archivos muy pequeños
            score += 0.2
        elif file_size > 50 * 1024 * 1024:  # Archivos muy grandes (>50MB)
            score += 0.1
        
        details['file_size'] = file_size
        
        # Verificar PE header para ejecutables Windows
        if content.startswith(b'MZ'):
            score += 0.2
            details['pe_file'] = True
        
        # Verificar strings sospechosos
        content_str = content.decode('utf-8', errors='ignore').lower()
        suspicious_strings = [
            'virus', 'trojan', 'backdoor', 'keylogger', 'rootkit',
            'payload', 'shellcode', 'exploit', 'malware'
        ]
        
        found_strings = [s for s in suspicious_strings if s in content_str]
        if found_strings:
            score += len(found_strings) * 0.1
            details['suspicious_strings'] = found_strings
        
        return {'score': min(score, 1.0), 'details': details}
    
    def _pattern_analysis(self, content: bytes) -> Dict:
        """Análisis de patrones sospechosos"""
        score = 0.0
        details = {}
        
        try:
            content_str = content.decode('utf-8', errors='ignore')
            
            matched_patterns = []
            for pattern in self.suspicious_patterns:
                matches = re.findall(pattern, content_str, re.IGNORECASE)
                if matches:
                    matched_patterns.append(pattern)
                    score += 0.15
            
            details['matched_patterns'] = matched_patterns
            details['pattern_count'] = len(matched_patterns)
            
        except Exception as e:
            logger.error(f"Error en análisis de patrones: {e}")
        
        return {'score': min(score, 1.0), 'details': details}
    
    def _entropy_analysis(self, content: bytes) -> Dict:
        """Análisis de entropía del archivo"""
        try:
            # Calcular entropía de Shannon
            if len(content) == 0:
                return {'score': 0.0, 'details': {'entropy': 0.0}}
            
            # Contar frecuencia de bytes
            byte_counts = np.bincount(content, minlength=256)
            probabilities = byte_counts / len(content)
            
            # Calcular entropía
            entropy = -np.sum([p * np.log2(p) for p in probabilities if p > 0])
            
            # Entropía alta puede indicar compresión o cifrado
            # Entropía muy alta (>7.5) es sospechosa
            score = 0.0
            if entropy > 7.5:
                score = 0.8
            elif entropy > 7.0:
                score = 0.4
            elif entropy < 1.0:  # Entropía muy baja también es sospechosa
                score = 0.3
            
            return {
                'score': score,
                'details': {
                    'entropy': entropy,
                    'is_high_entropy': entropy > 7.5,
                    'is_low_entropy': entropy < 1.0
                }
            }
            
        except Exception as e:
            logger.error(f"Error calculando entropía: {e}")
            return {'score': 0.0, 'details': {'error': str(e)}}

class ThreatIntelligence:
    """Integración con fuentes de threat intelligence"""
    
    def __init__(self):
        self.api_keys = {}
        self.cache = {}
        self.cache_ttl = 3600  # 1 hora
    
    def set_api_key(self, service: str, api_key: str):
        """Configurar API key para un servicio"""
        self.api_keys[service] = api_key
    
    async def check_ip_reputation(self, ip_address: str) -> Dict:
        """Verificar reputación de IP"""
        cache_key = f"ip_{ip_address}"
        
        # Verificar cache
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if datetime.now().timestamp() - timestamp < self.cache_ttl:
                return cached_data
        
        # Consultar fuentes externas
        reputation_data = await self._query_ip_sources(ip_address)
        
        # Guardar en cache
        self.cache[cache_key] = (reputation_data, datetime.now().timestamp())
        
        return reputation_data
    
    async def _query_ip_sources(self, ip_address: str) -> Dict:
        """Consultar múltiples fuentes de reputación de IPs"""
        results = {
            'is_malicious': False,
            'confidence': 0.0,
            'sources': [],
            'details': {}
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                
                # AbuseIPDB (requiere API key)
                if 'abuseipdb' in self.api_keys:
                    tasks.append(self._check_abuseipdb(session, ip_address))
                
                # VirusTotal (requiere API key)
                if 'virustotal' in self.api_keys:
                    tasks.append(self._check_virustotal_ip(session, ip_address))
                
                # Ejecutar consultas en paralelo
                source_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Procesar resultados
                malicious_count = 0
                total_sources = 0
                
                for result in source_results:
                    if isinstance(result, dict) and not isinstance(result, Exception):
                        total_sources += 1
                        results['sources'].append(result['source'])
                        
                        if result.get('is_malicious', False):
                            malicious_count += 1
                        
                        results['details'][result['source']] = result
                
                # Calcular confianza basada en consenso
                if total_sources > 0:
                    results['confidence'] = malicious_count / total_sources
                    results['is_malicious'] = results['confidence'] > 0.5
                
        except Exception as e:
            logger.error(f"Error consultando reputación de IP {ip_address}: {e}")
            results['details']['error'] = str(e)
        
        return results
    
    async def _check_abuseipdb(self, session: aiohttp.ClientSession, ip_address: str) -> Dict:
        """Consultar AbuseIPDB"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.api_keys['abuseipdb'],
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    abuse_confidence = data['data'].get('abuseConfidencePercentage', 0)
                    
                    return {
                        'source': 'abuseipdb',
                        'is_malicious': abuse_confidence > 25,
                        'confidence': abuse_confidence / 100,
                        'details': data['data']
                    }
                
        except Exception as e:
            logger.error(f"Error consultando AbuseIPDB: {e}")
        
        return {'source': 'virustotal', 'is_malicious': False, 'confidence': 0.0}

class ComprehensiveThreatAnalyzer:
    """Analizador principal que combina todos los módulos"""
    
    def __init__(self):
        self.network_analyzer = NetworkAnalyzer()
        self.malware_analyzer = MalwareAnalyzer()
        self.threat_intelligence = ThreatIntelligence()
        self.alert_threshold = 0.7
    
    def configure(self, config: Dict):
        """Configurar el analizador"""
        if 'alert_threshold' in config:
            self.alert_threshold = config['alert_threshold']
        
        if 'api_keys' in config:
            for service, key in config['api_keys'].items():
                self.threat_intelligence.set_api_key(service, key)
        
        if 'malware_signatures' in config:
            self.malware_analyzer.load_malware_signatures(config['malware_signatures'])
    
    async def analyze_comprehensive(self, threat_data: Dict) -> Dict:
        """Análisis comprehensivo de amenazas"""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'threat_data': threat_data,
            'analyses': {},
            'final_assessment': {}
        }
        
        try:
            analysis_type = threat_data.get('type', 'unknown')
            
            # Análisis de red
            if analysis_type in ['network', 'traffic']:
                network_result = self.network_analyzer.detect_anomaly(threat_data)
                results['analyses']['network'] = network_result
                
                # Verificar reputación de IP si está disponible
                source_ip = threat_data.get('source_ip')
                if source_ip:
                    ip_reputation = await self.threat_intelligence.check_ip_reputation(source_ip)
                    results['analyses']['ip_reputation'] = ip_reputation
            
            # Análisis de malware
            elif analysis_type in ['file', 'malware']:
                if 'file_hash' in threat_data:
                    hash_result = self.malware_analyzer.analyze_file_hash(threat_data['file_hash'])
                    results['analyses']['hash_analysis'] = hash_result
                
                if 'file_content' in threat_data:
                    content = threat_data['file_content']
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    
                    content_result = self.malware_analyzer.analyze_file_content(
                        content, threat_data.get('filename', '')
                    )
                    results['analyses']['content_analysis'] = content_result
            
            # Generar evaluación final
            final_assessment = self._generate_final_assessment(results['analyses'])
            results['final_assessment'] = final_assessment
            
            return results
            
        except Exception as e:
            logger.error(f"Error en análisis comprehensivo: {e}")
            results['final_assessment'] = {
                'is_threat': False,
                'confidence': 0.0,
                'severity': 'LOW',
                'threat_type': 'analysis_error',
                'error': str(e)
            }
            return results
    
    def _generate_final_assessment(self, analyses: Dict) -> Dict:
        """Generar evaluación final basada en todos los análisis"""
        if not analyses:
            return {
                'is_threat': False,
                'confidence': 0.0,
                'severity': 'LOW',
                'threat_type': 'no_analysis',
                'details': 'No se realizaron análisis'
            }
        
        # Recopilar scores de confianza
        confidence_scores = []
        threat_types = []
        is_threat_flags = []
        severities = []
        
        for analysis_name, analysis_result in analyses.items():
            if isinstance(analysis_result, dict):
                confidence_scores.append(analysis_result.get('confidence', 0.0))
                threat_types.append(analysis_result.get('threat_type', 'unknown'))
                is_threat_flags.append(analysis_result.get('is_threat', False))
                severities.append(analysis_result.get('severity', 'LOW'))
        
        if not confidence_scores:
            return {
                'is_threat': False,
                'confidence': 0.0,
                'severity': 'LOW',
                'threat_type': 'no_valid_analysis'
            }
        
        # Calcular confianza promedio ponderada
        avg_confidence = np.mean(confidence_scores)
        max_confidence = max(confidence_scores)
        
        # Determinar si es amenaza (cualquier análisis positivo con alta confianza)
        is_threat = any(is_threat_flags) and max_confidence > self.alert_threshold
        
        # Determinar severidad (usar la más alta)
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
        max_severity = max(severities, key=lambda x: severity_order.get(x, 0))
        
        # Determinar tipo de amenaza principal
        threat_type_counts = {}
        for tt in threat_types:
            threat_type_counts[tt] = threat_type_counts.get(tt, 0) + 1
        
        primary_threat_type = max(threat_type_counts.keys(), key=lambda x: threat_type_counts[x])
        
        return {
            'is_threat': is_threat,
            'confidence': max_confidence if is_threat else avg_confidence,
            'severity': max_severity if is_threat else 'LOW',
            'threat_type': primary_threat_type,
            'details': {
                'analyses_count': len(analyses),
                'avg_confidence': avg_confidence,
                'max_confidence': max_confidence,
                'threat_types': threat_type_counts,
                'positive_analyses': sum(is_threat_flags)
            }
        }
    
    def train_models(self, training_data: Dict):
        """Entrenar todos los modelos con datos de entrenamiento"""
        results = {}
        
        # Entrenar analizador de red
        if 'network_data' in training_data:
            network_success = self.network_analyzer.train(training_data['network_data'])
            results['network_analyzer'] = network_success
        
        # Cargar firmas de malware
        if 'malware_signatures' in training_data:
            self.malware_analyzer.load_malware_signatures(training_data['malware_signatures'])
            results['malware_signatures'] = True
        
        logger.info(f"Entrenamiento completado: {results}")
        return results
    
    def get_model_status(self) -> Dict:
        """Obtener estado de todos los modelos"""
        return {
            'network_analyzer': {
                'is_trained': self.network_analyzer.is_trained,
                'features': len(self.network_analyzer.feature_columns)
            },
            'malware_analyzer': {
                'signatures_loaded': len(self.malware_analyzer.known_signatures),
                'patterns_loaded': len(self.malware_analyzer.suspicious_patterns)
            },
            'threat_intelligence': {
                'api_keys_configured': len(self.threat_intelligence.api_keys),
                'cache_entries': len(self.threat_intelligence.cache)
            }
        }

# Funciones de utilidad
def calculate_file_hashes(file_content: bytes) -> Dict[str, str]:
    """Calcular múltiples hashes de un archivo"""
    return {
        'md5': hashlib.md5(file_content).hexdigest(),
        'sha1': hashlib.sha1(file_content).hexdigest(),
        'sha256': hashlib.sha256(file_content).hexdigest()
    }

def extract_network_features_from_pcap(pcap_data: bytes) -> Dict:
    """Extraer características de tráfico de red desde datos PCAP"""
    # Esta función requeriría una biblioteca como scapy para procesar PCAP
    # Por simplicidad, retornamos datos simulados
    return {
        'packet_count': 100,
        'unique_ips': 10,
        'protocols': ['TCP', 'UDP', 'ICMP'],
        'port_distribution': {'80': 30, '443': 40, '22': 5, 'other': 25},
        'packet_sizes': [64, 128, 256, 512, 1024, 1500],
        'time_span': 300  # 5 minutos
    }

def generate_threat_report(analysis_results: Dict) -> str:
    """Generar reporte legible de análisis de amenazas"""
    report = []
    report.append("=== REPORTE DE ANÁLISIS DE AMENAZAS ===\n")
    
    timestamp = analysis_results.get('timestamp', 'N/A')
    report.append(f"Timestamp: {timestamp}")
    
    final_assessment = analysis_results.get('final_assessment', {})
    
    if final_assessment.get('is_threat', False):
        report.append(f"\n🚨 AMENAZA DETECTADA")
        report.append(f"Tipo: {final_assessment.get('threat_type', 'Desconocido')}")
        report.append(f"Severidad: {final_assessment.get('severity', 'Desconocida')}")
        report.append(f"Confianza: {final_assessment.get('confidence', 0):.2%}")
    else:
        report.append(f"\n✅ NO SE DETECTARON AMENAZAS")
        report.append(f"Confianza: {final_assessment.get('confidence', 0):.2%}")
    
    # Detalles de análisis
    analyses = analysis_results.get('analyses', {})
    if analyses:
        report.append(f"\n--- Detalles de Análisis ---")
        for analysis_name, result in analyses.items():
            if isinstance(result, dict):
                report.append(f"\n{analysis_name.upper()}:")
                report.append(f"  - Es amenaza: {'Sí' if result.get('is_threat', False) else 'No'}")
                report.append(f"  - Confianza: {result.get('confidence', 0):.2%}")
                report.append(f"  - Severidad: {result.get('severity', 'N/A')}")
    
    return "\n".join(report)

# Instancia global del analizador
global_threat_analyzer = ComprehensiveThreatAnalyzer()

if __name__ == "__main__":
    # Ejemplo de uso
    import asyncio
    
    async def test_analyzer():
        analyzer = ComprehensiveThreatAnalyzer()
        
        # Configurar analizador
        config = {
            'alert_threshold': 0.7,
            'malware_signatures': [
                'd41d8cd98f00b204e9800998ecf8427e',
                '5d41402abc4b2a76b9719d911017c592'
            ]
        }
        analyzer.configure(config)
        
        # Datos de prueba para análisis de red
        network_test_data = {
            'type': 'network',
            'packet_size': 2000,
            'connection_count': 1500,
            'bandwidth_usage': 95,
            'port_scan_score': 80,
            'source_ip': '192.168.1.100'
        }
        
        # Realizar análisis
        results = await analyzer.analyze_comprehensive(network_test_data)
        
        # Generar reporte
        report = generate_threat_report(results)
        print(report)
        
        # Estado de modelos
        status = analyzer.get_model_status()
        print(f"\nEstado de modelos: {status}")
    
    # Ejecutar test
    asyncio.run(test_analyzer())abuseipdb', 'is_malicious': False, 'confidence': 0.0}
    
    async def _check_virustotal_ip(self, session: aiohttp.ClientSession, ip_address: str) -> Dict:
        """Consultar VirusTotal para IP"""
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'ip': ip_address
            }
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Procesar detecciones
                    detected_urls = data.get('detected_urls', [])
                    detected_samples = data.get('detected_samples', [])
                    
                    is_malicious = len(detected_urls) > 0 or len(detected_samples) > 0
                    confidence = min((len(detected_urls) + len(detected_samples)) / 10, 1.0)
                    
                    return {
                        'source': 'virustotal',
                        'is_malicious': is_malicious,
                        'confidence': confidence,
                        'details': {
                            'detected_urls': len(detected_urls),
                            'detected_samples': len(detected_samples)
                        }
                    }
                
        except Exception as e:
            logger.error(f"Error consultando VirusTotal: {e}")
        
        return {'source': '