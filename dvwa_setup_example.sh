#!/bin/bash
# Ejemplo de configuración para DVWA usando Docker
# Laboratorio 2 - Sección 4

echo "=== Configuración de DVWA para Laboratorio de Fuerza Bruta ==="

# Verificar si Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker no está instalado"
    echo "Instale Docker desde: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "1. Descargando imagen de DVWA..."
docker pull vulnerables/web-dvwa

echo "2. Ejecutando contenedor DVWA..."
docker run -d \
    --name dvwa-lab2 \
    -p 8080:80 \
    vulnerables/web-dvwa

echo "3. Esperando que DVWA esté listo..."
sleep 10

echo "4. Verificando estado del contenedor..."
docker ps | grep dvwa-lab2

echo ""
echo "=== CONFIGURACIÓN COMPLETADA ==="
echo "DVWA estará disponible en: http://localhost:8080"
echo ""
echo "Credenciales por defecto:"
echo "  Usuario: admin"
echo "  Contraseña: password"
echo ""
echo "IMPORTANTE:"
echo "1. Acceda a http://localhost:8080 y complete la configuración inicial"
echo "2. Configure el nivel de seguridad en 'Low' para las pruebas"
echo "3. Navegue a 'DVWA Security' y seleccione 'Low'"
echo "4. Vaya a 'Brute Force' para probar el script"
echo ""
echo "Para detener DVWA:"
echo "  docker stop dvwa-lab2"
echo "  docker rm dvwa-lab2"