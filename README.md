# Laboratorio 2 - Sección 4: Ataques de Fuerza Bruta

Este repositorio contiene el material desarrollado para el Laboratorio 2 de Seguridad Informática, enfocado en ataques de fuerza bruta contra aplicaciones web vulnerables (DVWA).

## Contenido

### Archivos Principales

- `brute_force_script.py` - Script de Python para realizar ataques de fuerza bruta
- `lab01_informe.tex` - Informe del laboratorio en formato LaTeX
- `requirements.txt` - Dependencias de Python necesarias

### Script de Fuerza Bruta

El script `brute_force_script.py` implementa:

1. **Ataque de fuerza bruta automatizado** usando la librería `requests`
2. **Análisis de cabeceras HTTP** utilizadas en el ataque
3. **Documentación de métodos de mitigación** de ataques de fuerza bruta
4. **Resultados y análisis** de credenciales encontradas

#### Características del Script

- Interacción con DVWA en `vulnerabilities/brute`
- Cabeceras HTTP realistas para evitar detección
- Lista configurable de usuarios y contraseñas
- Delay entre intentos para control de velocidad
- Detección automática de credenciales válidas
- Logging detallado del proceso

#### Cabeceras HTTP Importantes

El script utiliza las siguientes cabeceras críticas:

- **User-Agent**: Simula un navegador real
- **Cookie**: Mantiene la sesión DVWA (PHPSESSID, security level)
- **Accept**: Especifica tipos de contenido aceptados
- **Connection**: Optimiza la reutilización de conexiones

## Uso del Script

### Prerrequisitos

1. DVWA ejecutándose localmente o en servidor accesible
2. Python 3.6+ instalado
3. Dependencias instaladas: `pip install -r requirements.txt`

### Ejecución

```bash
python3 brute_force_script.py
```

El script incluye:
- Explicación interactiva de cabeceras HTTP
- Documentación de métodos de mitigación
- Ejecución del ataque de fuerza bruta
- Análisis de resultados

### Configuración de DVWA

Para usar el script efectivamente:

1. Configure DVWA con nivel de seguridad "Low"
2. Obtenga las cookies de sesión desde el navegador
3. Ajuste la URL base según su configuración

## Métodos de Mitigación Documentados

El script documenta 4 métodos principais de mitigación:

1. **Rate Limiting y Account Lockout**
2. **CAPTCHA Implementation**
3. **Multi-Factor Authentication (MFA)**
4. **IP-based Monitoring and Blocking**

Cada método incluye:
- Explicación de funcionamiento
- Escenarios de mayor eficacia
- Ventajas y desventajas
- Casos de uso recomendados

## Resultados Esperados

El script puede encontrar credenciales comunes como:
- admin:password
- admin:admin
- user:user
- (dependiendo de la configuración DVWA)

## Consideraciones Éticas

Este material es exclusivamente para:
- **Fines educativos** en entornos controlados
- **Investigación de seguridad** autorizada
- **Pruebas en sistemas propios** o con autorización explícita

**NO** debe utilizarse en sistemas sin autorización explícita.

## Estructura del Informe

El archivo `lab01_informe.tex` incluye secciones para:

- Configuración de DVWA con Docker
- Uso de herramientas (Burpsuite, cURL, Hydra)
- Implementación del script Python
- Análisis de tráfico y detección
- Métodos de mitigación
- Comparación de rendimiento

## Licencia

Material educativo para uso académico exclusivamente.