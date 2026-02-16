# Laboratorio 2 – Protección de datos

Este repositorio contiene el desarrollo del Laboratorio 2 del curso de Ciberseguridad.  
El objetivo fue analizar comunicaciones inseguras y aplicar mecanismos de protección en servicios de red.

## Estructura del repositorio

- `capturas/` → Archivos `.pcap` con evidencias de Wireshark  
- `CryptoPythonLab2.py` → Script de cifrado AES y transferencia por FTP  
- `README.md` → Documentación del proyecto  

---

## Objetivos

- Analizar tráfico inseguro de FTP y MySQL.
- Implementar mecanismos de protección.
- Comparar comunicaciones inseguras y seguras.

---

## Protección del servicio FTP

Inicialmente se evidenció que FTP transmite información en texto plano.  
Posteriormente se utilizó SFTP (basado en SSH), lo que permitió cifrar:

- Credenciales
- Archivos transferidos
- Sesión completa

En las capturas protegidas solo se observan paquetes SSH cifrados.

---

## Protección de la Base de Datos

Se configuró la base de datos para operar con TLS.

Se verificó el uso de cifrado mediante:

```
SHOW STATUS LIKE 'Ssl_cipher';
```

Confirmando el uso de un cipher seguro (TLS_AES_256_GCM_SHA384).

En Wireshark se observa tráfico TLSv1.3 con "Application Data", sin contenido legible.

---

## Cifrado de archivos con Python (AES)

Se desarrolló el script `CryptoPythonLab2.py`, el cual implementa:

- AES-256 en modo GCM
- Derivación de clave con PBKDF2
- Salt y nonce aleatorios
- Autenticación mediante tag GCM

### Instalación

```
pip install pycryptodome
```

### Uso

Cifrar:

```
python CryptoPythonLab2.py encrypt -i archivo.txt -o archivo.enc
```

Descifrar:

```
python CryptoPythonLab2.py decrypt -i archivo.enc -o archivo.txt
```

---

## Enfoque aplicado

Se aplicó el principio de defensa en profundidad:

- Cifrado en tránsito (SSH / TLS)
- Cifrado a nivel de aplicación (AES)
- Validación mediante análisis de tráfico
