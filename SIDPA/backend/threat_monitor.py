# SIDPA/backend/threat_monitor.py
import asyncio
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import redis
import numpy as np
from sqlalchemy.orm import Session
from database import SessionLocal, ThreatDetection, NetworkTraffic, SystemEvent
from threat_analyzer import ComprehensiveThreatAnalyzer
import psutil
import socket
import requests
from scapy.all import sniff, IP, TCP, UDP, ICMP

logger = logging.getLogger(__name__)

class RealTimeThreatMonitor:
    """Monitor en tiempo real para detección de amenazas"""
    
    def __init__(self):
        self.analyzer = ComprehensiveThreatAnalyzer()
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        self.is_monitoring = False
        self.monitoring_tasks = []
        
        # Configuración
        self.config = {
            'network_interface': 'eth0',
            'packet_capture_limit': 1000,
            'analysis_interval': 30,  # segundos
            'alert_threshold': 0.7,
            'max_alerts_per_hour': 100
        }
    
    async def start_monitoring(self):
        """Iniciar monitoreo en tiempo real"""
        self.is_monitoring = True
        logger.info("Iniciando monitoreo de amenazas en tiempo real")
        
        # Crear tareas de monitoreo
        tasks = [
            self.monitor_network_traffic(),
            self.monitor_system_events(),
            self.monitor_file_system(),
            self.analyze_periodic_data(),
            self.cleanup_old_data()
        ]
        
        self.monitoring_tasks = [asyncio.create_task(task) for task in tasks]
        
        # Ejecutar todas las tareas
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def stop_monitoring(self):
        """Detener monitoreo"""
        self.is_monitoring = False
        logger.info("Deteniendo monitoreo de amenazas")
        
        for task in self.monitoring_tasks:
            task.cancel()
        
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def monitor_network_traffic(self):
        """Monitor de tráfico de red"""
        while self.is_monitoring:
            try:
                # Capturar paquetes usando scapy
                packets = await self._capture_network_packets()
                
                if packets:
                    # Analizar patrones de tráfico
                    traffic_analysis = self._analyze_network_patterns(packets)
                    
                    # Detectar anomalías
                    if traffic_analysis['is_suspicious']:
                        await self._handle_network_threat(traffic_analysis)
                
                await asyncio.sleep(self.config['analysis_interval'])
                
            except Exception as e:
                logger.error(f"Error en monitor de red: {e}")
                await asyncio.sleep(10)
    
    async def monitor_system_events(self):
        """Monitor de eventos del sistema"""
        while self.is_monitoring:
            try:
                # Obtener información del sistema
                system_info = self._get_system_info()
                
                # Detectar procesos sospechosos
                suspicious_processes = self._detect_suspicious_processes()
                
                if suspicious_processes:
                    await self._handle_system_threat(suspicious_processes)
                
                # Monitor de recursos del sistema
                resource_analysis = self._analyze_system_resources(system_info)
                
                if resource_analysis['is_suspicious']:
                    await self._handle_resource_anomaly(resource_analysis)
                
                await asyncio.sleep(15)
                
            except Exception as e:
                logger.error(f"Error en monitor de sistema: {e}")
                await asyncio.sleep(10)
    
    async def monitor_file_system(self):
        """Monitor del sistema de archivos"""
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
        
        class ThreatFileHandler(FileSystemEventHandler):
            def __init__(self, monitor_instance):
                self.monitor = monitor_instance
            
            def on_created(self, event):
                if not event.is_directory:
                    asyncio.create_task(self.monitor._analyze_new_file(event.src_path))
            
            def on_modified(self, event):
                if not event.is_directory and event.src_path.endswith('.exe'):
                    asyncio.create_task(self.monitor._analyze_modified_file(event.src_path))
        
        observer = Observer()
        event_handler = ThreatFileHandler(self)
        
        # Monitorear directorios críticos
        critical_dirs = ['/tmp', '/var/tmp', '/Downloads', '/Documents']
        
        for directory in critical_dirs:
            try:
                observer.schedule(event_handler, directory, recursive=True)
            except Exception as e:
                logger.warning(f"No se pudo monitorear directorio {directory}: {e}")
        
        observer.start()
        
        while self.is_monitoring:
            await asyncio.sleep(60)
        
        observer.stop()
        observer.join()
    
    async def analyze_periodic_data(self):
        """Análisis periódico de datos acumulados"""
        while self.is_monitoring:
            try:
                # Analizar tendencias de amenazas
                trend_analysis = await self._analyze_threat_trends()
                
                # Generar reporte de estado
                status_report = await self._generate_status_report()
                
                # Publicar en Redis para dashboard
                await self._publish_status_update(status_report)
                
                # Entrenar modelos si hay suficientes datos nuevos
                await self._retrain_models_if_needed()
                
                await asyncio.sleep(300)  # 5 minutos
                
            except Exception as e:
                logger.error(f"Error en análisis periódico: {e}")
                await asyncio.sleep(60)
    
    async def cleanup_old_data(self):
        """Limpieza de datos antiguos"""
        while self.is_monitoring:
            try:
                db = SessionLocal()
                
                # Eliminar amenazas resueltas y antiguas (>30 días)
                cutoff_date = datetime.utcnow() - timedelta(days=30)
                
                old_threats = db.query(ThreatDetection).filter(
                    ThreatDetection.is_resolved == True,
                    ThreatDetection.timestamp < cutoff_date
                ).delete()
                
                # Eliminar tráfico de red antiguo (>7 días)
                network_cutoff = datetime.utcnow() - timedelta(days=7)
                old_traffic = db.query(NetworkTraffic).filter(
                    NetworkTraffic.timestamp < network_cutoff
                ).delete()
                
                db.commit()
                db.close()
                
                logger.info(f"Limpieza completada: {old_threats} amenazas, {old_traffic} tráfico")
                
                # Esperar 24 horas para la próxima limpieza
                await asyncio.sleep(86400)
                
            except Exception as e:
                logger.error(f"Error en limpieza de datos: {e}")
                await asyncio.sleep(3600)  # Reintentar en 1 hora
    
    async def _capture_network_packets(self) -> List[Dict]:
        """Capturar paquetes de red usando scapy"""
        packets = []
        
        def packet_handler(pkt):
            if IP in pkt:
                packet_info = {
                    'timestamp': datetime.utcnow().timestamp(),
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'protocol': pkt[IP].proto,
                    'length': len(pkt),
                    'flags': []
                }
                
                if TCP in pkt:
                    packet_info['src_port'] = pkt[TCP].sport
                    packet_info['dst_port'] = pkt[TCP].dport
                    packet_info['flags'] = str(pkt[TCP].flags)
                elif UDP in pkt:
                    packet_info['src_port'] = pkt[UDP].sport
                    packet_info['dst_port'] = pkt[UDP].dport
                
                packets.append(packet_info)
        
        try:
            # Capturar paquetes por 10 segundos
            sniff(iface=self.config['network_interface'], 
                  prn=packet_handler, 
                  timeout=10, 
                  count=self.config['packet_capture_limit'])
        except Exception as e:
            logger.error(f"Error capturando paquetes: {e}")
        
        return packets
    
    def _analyze_network_patterns(self, packets: List[Dict]) -> Dict:
        """Analizar patrones en el tráfico de red"""
        if not packets:
            return {'is_suspicious': False, 'details': {}}
        
        analysis = {
            'is_suspicious': False,
            'total_packets': len(packets),
            'unique_ips': len(set(p['src_ip'] for p in packets)),
            'port_scan_score': 0,
            'ddos_score': 0,
            'suspicious_ports': [],
            'details': {}
        }
        
        # Detectar escaneo de puertos
        port_attempts = {}
        for packet in packets:
            if 'dst_port' in packet:
                key = f"{packet['src_ip']}:{packet['dst_ip']}"
                if key not in port_attempts:
                    port_attempts[key] = set()
                port_attempts[key].add(packet['dst_port'])
        
        # Verificar intentos de conexión a múltiples puertos
        for key, ports in port_attempts.items():
            if len(ports) > 20:  # Más de 20 puertos diferentes
                analysis['port_scan_score'] += len(ports)
                analysis['is_suspicious'] = True
        
        # Detectar posible DDoS
        ip_packet_count = {}
        for packet in packets:
            src_ip = packet['src_ip']
            ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1
        
        max_packets = max(ip_packet_count.values()) if ip_packet_count else 0
        if max_packets > len(packets) * 0.3:  # Una IP genera >30% del tráfico
            analysis['ddos_score'] = max_packets
            analysis['is_suspicious'] = True
        
        # Verificar puertos sospechosos
        suspicious_ports = [1337, 31337, 4444, 5555, 6666, 8080, 9999]
        for packet in packets:
            if 'dst_port' in packet and packet['dst_port'] in suspicious_ports:
                analysis['suspicious_ports'].append(packet['dst_port'])
                analysis['is_suspicious'] = True
        
        return analysis
    
    def _get_system_info(self) -> Dict:
        """Obtener información del sistema"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'boot_time': psutil.boot_time(),
            'users': [u._asdict() for u in psutil.users()]
        }
    
    def _detect_suspicious_processes(self) -> List[Dict]:
        """Detectar procesos sospechosos"""
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    info = proc.info
                    
                    # Procesos con alto uso de CPU/memoria
                    if info['cpu_percent'] > 80 or info['memory_percent'] > 50:
                        suspicious.append({
                            'type': 'high_resource_usage',
                            'process': info,
                            'severity': 'MEDIUM'
                        })
                    
                    # Procesos con nombres sospechosos
                    suspicious_names = ['miner', 'trojan', 'keylog', 'backdoor', 'rootkit']
                    if any(name in info['name'].lower() for name in suspicious_names):
                        suspicious.append({
                            'type': 'suspicious_name',
                            'process': info,
                            'severity': 'HIGH'
                        })
                    
                    # Procesos ejecutándose desde ubicaciones sospechosas
                    try:
                        exe_path = proc.exe()
                        suspicious_paths = ['/tmp/', '/var/tmp/', 'AppData\\Temp\\']
                        if any(path in exe_path for path in suspicious_paths):
                            suspicious.append({
                                'type': 'suspicious_location',
                                'process': info,
                                'exe_path': exe_path,
                                'severity': 'HIGH'
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logger.error(f"Error detectando procesos: {e}")
        
        return suspicious
    
    def _analyze_system_resources(self, system_info: Dict) -> Dict:
        """Analizar uso de recursos del sistema"""
        analysis = {
            'is_suspicious': False,
            'alerts': []
        }
        
        # CPU alto por tiempo prolongado
        if system_info['cpu_percent'] > 90:
            analysis['is_suspicious'] = True
            analysis['alerts'].append({
                'type': 'high_cpu',
                'value': system_info['cpu_percent'],
                'severity': 'MEDIUM'
            })
        
        # Memoria casi agotada
        if system_info['memory_percent'] > 95:
            analysis['is_suspicious'] = True
            analysis['alerts'].append({
                'type': 'high_memory',
                'value': system_info['memory_percent'],
                'severity': 'MEDIUM'
            })
        
        # Disco casi lleno
        if system_info['disk_usage'] > 95:
            analysis['alerts'].append({
                'type': 'disk_full',
                'value': system_info['disk_usage'],
                'severity': 'LOW'
            })
        
        return analysis
    
    async def _analyze_new_file(self, file_path: str):
        """Analizar nuevo archivo creado"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Leer primer MB
            
            # Usar el analizador de malware
            analysis = self.analyzer.malware_analyzer.analyze_file_content(content, file_path)
            
            if analysis['is_threat']:
                await self._handle_file_threat(file_path, analysis)
        
        except Exception as e:
            logger.error(f"Error analizando archivo {file_path}: {e}")
    
    async def _analyze_modified_file(self, file_path: str):
        """Analizar archivo modificado"""
        await self._analyze_new_file(file_path)
    
    async def _handle_network_threat(self, analysis: Dict):
        """Manejar amenaza de red detectada"""
        db = SessionLocal()
        try:
            threat = ThreatDetection(
                threat_type='network_anomaly',
                severity='HIGH' if analysis['port_scan_score'] > 50 else 'MEDIUM',
                confidence=min(analysis['port_scan_score'] / 100, 1.0),
                description=f"Anomalía de red detectada: {analysis}",
                raw_data=json.dumps(analysis)
            )
            
            db.add(threat)
            db.commit()
            
            # Publicar alerta en tiempo real
            await self._publish_alert({
                'id': threat.id,
                'type': 'network_anomaly',
                'severity': threat.severity,
                'timestamp': threat.timestamp.isoformat(),
                'details': analysis
            })
            
        except Exception as e:
            logger.error(f"Error manejando amenaza de red: {e}")
        finally:
            db.close()
    
    async def _handle_system_threat(self, suspicious_processes: List[Dict]):
        """Manejar amenaza del sistema"""
        db = SessionLocal()
        try:
            for proc_threat in suspicious_processes:
                threat = ThreatDetection(
                    threat_type='suspicious_process',
                    severity=proc_threat['severity'],
                    confidence=0.8,
                    description=f"Proceso sospechoso detectado: {proc_threat['process']['name']}",
                    raw_data=json.dumps(proc_threat)
                )
                
                db.add(threat)
                db.commit()
                
                await self._publish_alert({
                    'id': threat.id,
                    'type': 'suspicious_process',
                    'severity': threat.severity,
                    'timestamp': threat.timestamp.isoformat(),
                    'process': proc_threat['process']['name']
                })
                
        except Exception as e:
            logger.error(f"Error manejando amenaza del sistema: {e}")
        finally:
            db.close()
    
    async def _handle_resource_anomaly(self, analysis: Dict):
        """Manejar anomalía de recursos"""
        for alert in analysis['alerts']:
            await self._publish_alert({
                'type': 'resource_anomaly',
                'severity': alert['severity'],
                'timestamp': datetime.utcnow().isoformat(),
                'resource_type': alert['type'],
                'value': alert['value']
            })
    
    async def _handle_file_threat(self, file_path: str, analysis: Dict):
        """Manejar amenaza de archivo"""
        db = SessionLocal()
        try:
            threat = ThreatDetection(
                threat_type='malicious_file',
                severity=analysis['severity'],
                confidence=analysis['confidence'],
                description=f"Archivo malicioso detectado: {file_path}",
                raw_data=json.dumps({
                    'file_path': file_path,
                    'analysis': analysis
                })
            )
            
            db.add(threat)
            db.commit()
            
            await self._publish_alert({
                'id': threat.id,
                'type': 'malicious_file',
                'severity': threat.severity,
                'timestamp': threat.timestamp.isoformat(),
                'file_path': file_path
            })
            
        except Exception as e:
            logger.error(f"Error manejando amenaza de archivo: {e}")
        finally:
            db.close()
    
    async def _publish_alert(self, alert_data: Dict):
        """Publicar alerta en Redis para tiempo real"""
        try:
            self.redis_client.publish('threat_alerts', json.dumps(alert_data))
            logger.info(f"Alerta publicada: {alert_data['type']}")
        except Exception as e:
            logger.error(f"Error publicando alerta: {e}")
    
    async def _analyze_threat_trends(self) -> Dict:
        """Analizar tendencias de amenazas"""
        db = SessionLocal()
        try:
            # Amenazas en las últimas 24 horas
            last_24h = datetime.utcnow() - timedelta(hours=24)
            recent_threats = db.query(ThreatDetection).filter(
                ThreatDetection.timestamp > last_24h
            ).all()
            
            # Análisis de tendencias
            trends = {
                'total_last_24h': len(recent_threats),
                'by_type': {},
                'by_severity': {},
                'hourly_distribution': [0] * 24
            }
            
            for threat in recent_threats:
                # Por tipo
                t_type = threat.threat_type
                trends['by_type'][t_type] = trends['by_type'].get(t_type, 0) + 1
                
                # Por severidad
                severity = threat.severity
                trends['by_severity'][severity] = trends['by_severity'].get(severity, 0) + 1
                
                # Distribución horaria
                hour = threat.timestamp.hour
                trends['hourly_distribution'][hour] += 1
            
            return trends
            
        except Exception as e:
            logger.error(f"Error analizando tendencias: {e}")
            return {}
        finally:
            db.close()
    
    async def _generate_status_report(self) -> Dict:
        """Generar reporte de estado del sistema"""
        system_info = self._get_system_info()
        trends = await self._analyze_threat_trends()
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'system_status': {
                'cpu_usage': system_info['cpu_percent'],
                'memory_usage': system_info['memory_percent'],
                'disk_usage': system_info['disk_usage'],
                'monitoring_active': self.is_monitoring
            },
            'threat_trends': trends,
            'model_status': self.analyzer.get_model_status()
        }
    
    async def _publish_status_update(self, status_report: Dict):
        """Publicar actualización de estado"""
        try:
            self.redis_client.setex('system_status', 3600, json.dumps(status_report))
        except Exception as e:
            logger.error(f"Error publicando estado: {e}")
    
    async def _retrain_models_if_needed(self):
        """Entrenar modelos si hay suficientes datos nuevos"""
        try:
            db = SessionLocal()
            
            # Verificar si hay suficientes datos nuevos para reentrenamiento
            last_week = datetime.utcnow() - timedelta(days=7)
            new_threats = db.query(ThreatDetection).filter(
                ThreatDetection.timestamp > last_week,
                ThreatDetection.is_resolved == True
            ).count()
            
            if new_threats > 100:  # Umbral para reentrenamiento
                logger.info(f"Iniciando reentrenamiento con {new_threats} nuevas amenazas")
                # Aquí iría la lógica de reentrenamiento
                # training_data = self._prepare_training_data(db)
                # self.analyzer.train_models(training_data)
            
            db.close()
            
        except Exception as e:
            logger.error(f"Error en reentrenamiento: {e}")

# Función principal para ejecutar el monitor
async def main():
    monitor = RealTimeThreatMonitor()
    
    try:
        await monitor.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Deteniendo monitor por interrupción del usuario")
    except Exception as e:
        logger.error(f"Error en monitor principal: {e}")
    finally:
        await monitor.stop_monitoring()

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(main())
