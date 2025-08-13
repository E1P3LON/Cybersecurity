# SIDPA - Sistema Inteligente de Detección y Prevención de Amenazas

## Descripción
SIDPA es un sistema avanzado de ciberseguridad que integra IA, machine learning y análisis en tiempo real para la detección y prevención de amenazas.

## Estructura del Proyecto
```
SIDPA/
├── .github/
│   └── workflows/
│       └── ci-cd.yml
├── backend/
│   ├── app/
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
└── README.md
```

## Requisitos Previos
- Python 3.10+
- Node.js 18+
- PostgreSQL
- MongoDB
- Redis
- Docker

## Configuración del Entorno de Desarrollo

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # En Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend
```bash
cd frontend
npm install
```

## Ejecución del Proyecto

### Backend
```bash
cd backend
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm start
```

## Testing
- Backend: `pytest`
- Frontend: `npm test`

## Linting
- Backend: `pylint **/*.py`
- Frontend: `npm run lint`

## CI/CD
El proyecto utiliza GitHub Actions para:
- Testing automático
- Linting
- Análisis de seguridad
- Escaneo de vulnerabilidades

## Estándares de Código
- Backend: PEP 8
- Frontend: ESLint con configuración TypeScript
- Commits: Conventional Commits

## Metodología de Desarrollo
- Scrum
- Sprints de 2 semanas
- Code Review obligatorio
- Testing continuo

## Seguridad
- OWASP Top 10 compliance
- Escaneo regular de dependencias
- Análisis estático de código
- Pruebas de penetración automatizadas
