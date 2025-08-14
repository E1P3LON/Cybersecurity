import React, { useState, useEffect } from 'react';
import {
  AppBar, Toolbar, Typography, Container, Grid, Paper,
  Card, CardContent, CardActions, Button, Dialog,
  DialogTitle, DialogContent, TextField, Alert,
  Chip, IconButton, Drawer, List, ListItem,
  ListItemIcon, ListItemText, Badge
} from '@material-ui/core';
import {
  Security, Dashboard, Warning, CheckCircle,
  TrendingUp, Menu, Notifications, Settings,
  BugReport, NetworkCheck, Computer
} from '@material-ui/icons';
import { makeStyles, createTheme, ThemeProvider } from '@material-ui/core/styles';
import axios from 'axios';

// Configuración del tema
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#f5f5f5',
    },
  },
});

const useStyles = makeStyles((theme) => ({
  root: {
    flexGrow: 1,
  },
  appBar: {
    zIndex: theme.zIndex.drawer + 1,
  },
  drawer: {
    width: 240,
    flexShrink: 0,
  },
  drawerPaper: {
    width: 240,
  },
  drawerContainer: {
    overflow: 'auto',
  },
  content: {
    flexGrow: 1,
    padding: theme.spacing(3),
    marginLeft: 240,
  },
  paper: {
    padding: theme.spacing(2),
    textAlign: 'center',
    color: theme.palette.text.secondary,
    height: '100%',
  },
  threatCard: {
    margin: theme.spacing(1),
    '&.high': {
      borderLeft: `5px solid ${theme.palette.error.main}`,
    },
    '&.medium': {
      borderLeft: `5px solid ${theme.palette.warning.main}`,
    },
    '&.low': {
      borderLeft: `5px solid ${theme.palette.success.main}`,
    },
  },
  statCard: {
    textAlign: 'center',
    padding: theme.spacing(2),
  },
  alertDialog: {
    minWidth: 400,
  },
}));

// Interfaces TypeScript
interface ThreatData {
  id: number;
  threat_type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number;
  source_ip: string;
  timestamp: string;
  description: string;
  is_resolved: boolean;
}

interface StatsData {
  total_threats: number;
  high_severity: number;
  resolved: number;
  pending: number;
  threat_types: Record<string, number>;
}

interface AlertData {
  id: number;
  type: string;
  severity: string;
  timestamp: string;
  confidence: number;
}

const App: React.FC = () => {
  const classes = useStyles();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [threats, setThreats] = useState<ThreatData[]>([]);
  const [stats, setStats] = useState<StatsData | null>(null);
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [loginDialog, setLoginDialog] = useState(false);
  const [threatDialog, setThreatDialog] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(true);
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [threatTestData, setThreatTestData] = useState({
    type: 'network',
    packet_size: 1000,
    connection_count: 50,
    bandwidth_usage: 80,
    port_scan_score: 30,
    source_ip: '192.168.1.100'
  });

  // Configurar axios con token
  const api = axios.create({
    baseURL: 'http://localhost:8000',
  });

  api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  // Efectos
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      setIsAuthenticated(true);
      loadData();
      setupRealTimeAlerts();
    } else {
      setLoginDialog(true);
    }
  }, []);

  // Funciones de autenticación
  const handleLogin = async () => {
    try {
      const response = await api.post('/auth/login', credentials);
      localStorage.setItem('token', response.data.access_token);
      setIsAuthenticated(true);
      setLoginDialog(false);
      loadData();
      setupRealTimeAlerts();
    } catch (error) {
      console.error('Error de login:', error);
      alert('Credenciales incorrectas');
    }
  };

  // Cargar datos
  const loadData = async () => {
    try {
      const [threatsRes, statsRes] = await Promise.all([
        api.get('/threats'),
        api.get('/threats/stats')
      ]);
      setThreats(threatsRes.data);
      setStats(statsRes.data);
    } catch (error) {
      console.error('Error cargando datos:', error);
    }
  };

  // Configurar alertas en tiempo real
  const setupRealTimeAlerts = () => {
    const eventSource = new EventSource('http://localhost:8000/alerts/stream');
    eventSource.onmessage = (event) => {
      const alert: AlertData = JSON.parse(event.data);
      setAlerts(prev => [alert, ...prev.slice(0, 9)]);
      
      // Recargar datos cuando hay nueva amenaza
      loadData();
    };
  };

  // Probar detección de amenazas
  const testThreatDetection = async () => {
    try {
      const response = await api.post('/threats/detect', threatTestData);
      setThreatDialog(false);
      loadData();
      
      if (response.data.is_threat) {
        alert(`¡Amenaza detectada! Tipo: ${response.data.threat_type}, Severidad: ${response.data.severity}`);
      } else {
        alert('No se detectaron amenazas');
      }
    } catch (error) {
      console.error('Error en detección:', error);
      alert('Error al probar detección');
    }
  };

  // Resolver amenaza
  const resolveThreat = async (threatId: number) => {
    try {
      await api.put(`/threats/${threatId}/resolve`);
      loadData();
    } catch (error) {
      console.error('Error resolviendo amenaza:', error);
    }
  };

  // Entrenar modelo
  const trainModel = async () => {
    try {
      await api.post('/model/train');
      alert('Modelo entrenado exitosamente');
    } catch (error) {
      console.error('Error entrenando modelo:', error);
    }
  };

  // Obtener color de severidad
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'HIGH': return 'error';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'success';
      default: return 'default';
    }
  };

  if (!isAuthenticated) {
    return (
      <ThemeProvider theme={theme}>
        <Dialog open={loginDialog} maxWidth="sm" fullWidth>
          <DialogTitle>Iniciar Sesión - SIDPA</DialogTitle>
          <DialogContent>
            <TextField
              fullWidth
              label="Usuario"
              margin="normal"
              value={credentials.username}
              onChange={(e) => setCredentials({...credentials, username: e.target.value})}
            />
            <TextField
              fullWidth
              type="password"
              label="Contraseña"
              margin="normal"
              value={credentials.password}
              onChange={(e) => setCredentials({...credentials, password: e.target.value})}
            />
            <Button
              fullWidth
              variant="contained"
              color="primary"
              onClick={handleLogin}
              style={{ marginTop: 16 }}
            >
              Iniciar Sesión
            </Button>
            <Alert severity="info" style={{ marginTop: 16 }}>
              Usuario de prueba: admin / admin123
            </Alert>
          </DialogContent>
        </Dialog>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <div className={classes.root}>
        {/* AppBar */}
        <AppBar position="fixed" className={classes.appBar}>
          <Toolbar>
            <IconButton
              edge="start"
              color="inherit"
              onClick={() => setDrawerOpen(!drawerOpen)}
            >
              <Menu />
            </IconButton>
            <Security style={{ marginRight: 8 }} />
            <Typography variant="h6" style={{ flexGrow: 1 }}>
              SIDPA - Sistema Inteligente de Detección y Prevención de Amenazas
            </Typography>
            <IconButton color="inherit">
              <Badge badgeContent={alerts.length} color="secondary">
                <Notifications />
              </Badge>
            </IconButton>
          </Toolbar>
        </AppBar>

        {/* Drawer */}
        <Drawer
          className={classes.drawer}
          variant="persistent"
          anchor="left"
          open={drawerOpen}
          classes={{
            paper: classes.drawerPaper,
          }}
        >
          <Toolbar />
          <div className={classes.drawerContainer}>
            <List>
              <ListItem button>
                <ListItemIcon><Dashboard /></ListItemIcon>
                <ListItemText primary="Dashboard" />
              </ListItem>
              <ListItem button>
                <ListItemIcon><Warning /></ListItemIcon>
                <ListItemText primary="Amenazas" />
              </ListItem>
              <ListItem button>
                <ListItemIcon><NetworkCheck /></ListItemIcon>
                <ListItemText primary="Monitoreo de Red" />
              </ListItem>
              <ListItem button>
                <ListItemIcon><Computer /></ListItemIcon>
                <ListItemText primary="Análisis de Malware" />
              </ListItem>
              <ListItem button>
                <ListItemIcon><Settings /></ListItemIcon>
                <ListItemText primary="Configuración" />
              </ListItem>
            </List>
          </div>
        </Drawer>

        {/* Contenido principal */}
        <main className={classes.content}>
          <Toolbar />
          <Container maxWidth="xl">
            {/* Estadísticas */}
            <Grid container spacing={3} style={{ marginBottom: 24 }}>
              <Grid item xs={12} sm={6} md={3}>
                <Paper className={classes.statCard}>
                  <Typography variant="h4" color="primary">
                    {stats?.total_threats || 0}
                  </Typography>
                  <Typography variant="subtitle1">
                    Amenazas Totales
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper className={classes.statCard}>
                  <Typography variant="h4" color="error">
                    {stats?.high_severity || 0}
                  </Typography>
                  <Typography variant="subtitle1">
                    Severidad Alta
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper className={classes.statCard}>
                  <Typography variant="h4" color="secondary">
                    {stats?.pending || 0}
                  </Typography>
                  <Typography variant="subtitle1">
                    Pendientes
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper className={classes.statCard}>
                  <Typography variant="h4" style={{ color: '#4caf50' }}>
                    {stats?.resolved || 0}
                  </Typography>
                  <Typography variant="subtitle1">
                    Resueltas
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Botones de acción */}
            <Grid container spacing={2} style={{ marginBottom: 24 }}>
              <Grid item>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<BugReport />}
                  onClick={() => setThreatDialog(true)}
                >
                  Probar Detección
                </Button>
              </Grid>
              <Grid item>
                <Button
                  variant="outlined"
                  color="primary"
                  startIcon={<TrendingUp />}
                  onClick={trainModel}
                >
                  Entrenar Modelo
                </Button>
              </Grid>
              <Grid item>
                <Button
                  variant="outlined"
                  onClick={loadData}
                >
                  Actualizar Datos
                </Button>
              </Grid>
            </Grid>

            {/* Lista de amenazas */}
            <Paper style={{ padding: 16 }}>
              <Typography variant="h6" gutterBottom>
                Amenazas Recientes
              </Typography>
              <Grid container spacing={2}>
                {threats.map((threat) => (
                  <Grid item xs={12} md={6} lg={4} key={threat.id}>
                    <Card className={`${classes.threatCard} ${threat.severity.toLowerCase()}`}>
                      <CardContent>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography variant="h6">
                            {threat.threat_type.replace('_', ' ').toUpperCase()}
                          </Typography>
                          <Chip
                            label={threat.severity}
                            color={getSeverityColor(threat.severity) as any}
                            size="small"
                          />
                        </div>
                        <Typography color="textSecondary" gutterBottom>
                          IP: {threat.source_ip}
                        </Typography>
                        <Typography variant="body2">
                          {threat.description}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          Confianza: {(threat.confidence * 100).toFixed(1)}%
                        </Typography>
                        <br />
                        <Typography variant="caption" color="textSecondary">
                          {new Date(threat.timestamp).toLocaleString()}
                        </Typography>
                      </CardContent>
                      <CardActions>
                        {!threat.is_resolved ? (
                          <Button
                            size="small"
                            color="primary"
                            onClick={() => resolveThreat(threat.id)}
                          >
                            Resolver
                          </Button>
                        ) : (
                          <Chip
                            label="Resuelto"
                            color="primary"
                            size="small"
                            icon={<CheckCircle />}
                          />
                        )}
                      </CardActions>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            {/* Dialog para probar detección */}
            <Dialog open={threatDialog} onClose={() => setThreatDialog(false)}>
              <DialogTitle>Probar Detección de Amenazas</DialogTitle>
              <DialogContent>
                <TextField
                  fullWidth
                  label="Tipo"
                  margin="normal"
                  value={threatTestData.type}
                  onChange={(e) => setThreatTestData({...threatTestData, type: e.target.value})}
                />
                <TextField
                  fullWidth
                  type="number"
                  label="Tamaño de Paquete"
                  margin="normal"
                  value={threatTestData.packet_size}
                  onChange={(e) => setThreatTestData({...threatTestData, packet_size: parseInt(e.target.value)})}
                />
                <TextField
                  fullWidth
                  type="number"
                  label="Conexiones"
                  margin="normal"
                  value={threatTestData.connection_count}
                  onChange={(e) => setThreatTestData({...threatTestData, connection_count: parseInt(e.target.value)})}
                />
                <TextField
                  fullWidth
                  type="number"
                  label="Uso de Ancho de Banda (%)"
                  margin="normal"
                  value={threatTestData.bandwidth_usage}
                  onChange={(e) => setThreatTestData({...threatTestData, bandwidth_usage: parseInt(e.target.value)})}
                />
                <TextField
                  fullWidth
                  label="IP Origen"
                  margin="normal"
                  value={threatTestData.source_ip}
                  onChange={(e) => setThreatTestData({...threatTestData, source_ip: e.target.value})}
                />
                <Button
                  fullWidth
                  variant="contained"
                  color="primary"
                  onClick={testThreatDetection}
                  style={{ marginTop: 16 }}
                >
                  Ejecutar Detección
                </Button>
              </DialogContent>
            </Dialog>
          </Container>
        </main>
      </div>
    </ThemeProvider>
  );
};

export default App;