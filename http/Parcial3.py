import json
import re
import requests

# Patrón regex para extraer IP, fecha, hora, método, ruta y código de estado
patron_log = r'(\d{1,3}(?:\.\d{1,3}){3}) - - \[(\d{2}/[a-zA-Z]{3}/\d{4}):(\d{2}:\d{2}:\d{2}) .*?] "(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) ([^ ]+) HTTP/\d\.\d" (\d{3})'

contenido_logs = ""
# Leer archivos de log
for indice in range(3): 
    nombre_archivo = fr"C:\Users\Juanito\Downloads\SotM34-anton\SotM34-anton\SotM34\http\access_log{'' if indice == 0 else '.' + str(indice)}"
    try:
        with open(nombre_archivo, "r", encoding="utf-8", errors="ignore") as archivo:
            contenido_logs += archivo.read()
    except FileNotFoundError:
        continue  # Ignorar si algún archivo no existe

# Buscar coincidencias con regex
entradas = re.findall(patron_log, contenido_logs)

# Diccionario para agrupar ataques por país
registro_por_pais = {}

# Diccionario cache para evitar múltiples consultas a la misma IP
geo_cache = {}

# Procesamiento de cada entrada
for ip, fecha, hora, metodo, ruta, codigo in entradas:
    if ip not in geo_cache:
        try:
            geo = requests.get(f"http://ip-api.com/json/{ip}").json()
            pais = geo.get("country", "Desconocido") if geo.get("status") == "success" else "Desconocido"
        except:
            pais = "Desconocido"
        geo_cache[ip] = pais
    else:
        pais = geo_cache[ip]

    evento = {
        "fecha": fecha,
        "método": metodo,
        "ruta": ruta
    }

    if pais not in registro_por_pais:
        registro_por_pais[pais] = []
    registro_por_pais[pais].append(evento)

# Crear estructura final para JSON
salida_json = [{"Country": pais, "Attacks": lista} for pais, lista in registro_por_pais.items()]

# Guardar en archivo
with open("ataques_por_pais.json", "w", encoding="utf-8") as archivo_salida:
    json.dump(salida_json, archivo_salida, indent=4, ensure_ascii=False)

# Mostrar en consola
print(json.dumps(salida_json, indent=4, ensure_ascii=False))
