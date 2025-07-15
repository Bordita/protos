# Proxy SOCKSv5 con Esteroides - Grupo 9
**Trabajo Práctico Especial - Protocolos de Comunicación 2025**

## Índice
1. [Descripción General](#descripción-general)
2. [Ubicación de Materiales](#ubicación-de-materiales)
3. [Construcción del Proyecto](#construcción-del-proyecto)
4. [Artefactos Generados](#artefactos-generados)
5. [Ejecución](#ejecución)
6. [Opciones de Configuración](#opciones-de-configuración)
7. [Protocolo de Administración](#protocolo-de-administración)
8. [Logging y Monitoreo](#logging-y-monitoreo)
9. [Ejemplos de Uso](#ejemplos-de-uso)

## Descripción General

Este proyecto implementa un servidor proxy SOCKSv5 según RFC 1928 y RFC 1929, a diferencia del estándar pedido, el proxy solo acepta conexiones de tipo TCP, y no UDP, no provee soporte para autenticación mediante GSSAPI, y solo acepta pedidos del comando CONNECT. El sistema incluye:

- **Servidor Proxy SOCKSv5**: Maneja conexiones concurrentes (hasta 500+) con autenticación usuario/contraseña
- **Cliente de Administración**: Permite configuración y monitoreo en tiempo real
- **Protocolo HotDogs**: Protocolo propietario para administración del servidor
- **Sistema de Logging**: Registra accesos y actividades administrativas
- **Sistema de Métricas**: Recolecta estadísticas de funcionamiento

## Ubicación de Materiales

```
protos/
├── README.md                     # Este archivo
├── Makefile                      # Archivo de construcción principal
├── Makefile.inc                  # Configuraciones de compilación
├── doc/                          # Documentación
│   ├── Informe-TPE-G9.pdf        # Informe del trabajo práctico
│   ├── client.8                  # Manual del cliente
│   ├── socks5d.8                 # Manual del servidor
│   ├── concurrenceTest.8         # Manual del test de concurrencia
│   └── HotDogsProtocol.txt       # Especificación del protocolo HotDogs
├── src/                          # Código fuente
│   ├── server/                   # Servidor SOCKSv5
│   ├── client/                   # Cliente de administración
│   ├── shared/                   # Código compartido
│   ├── args/                     # Procesamiento de argumentos
│   └── test/                     # Herramientas de testing
└── bin/                          # Ejecutables generados (después de make)
```

## Construcción del Proyecto

### Requerimientos
- **Compilador**: GCC con soporte C11
- **Sistema Operativo**: Linux/Unix

### Comandos de Construcción

```bash
# Construcción completa
make clean all

# Limpiar proyecto
make clean
```

## Artefactos Generados

Después de ejecutar `make all`, se generan los siguientes ejecutables en `./bin/`:

| Archivo | Descripción |
|---------|-------------|
| `socks5d` | Servidor proxy SOCKSv5 principal |
| `client` | Cliente de administración HotDogs |
| `concurrenceTest` | Herramienta de testing de concurrencia |

### Archivos de Log Generados

| Archivo | Descripción |
|---------|-------------|
| `access.log` | Registro de accesos SOCKSv5 |
| `hotdogs_access.log` | Accesos al protocolo de administración |
| `hotdogs_actions.log` | Acciones administrativas ejecutadas |

## Ejecución

### Servidor SOCKSv5

```bash
# Ejecución básica
./bin/socks5d

# Con usuarios predefinidos
./bin/socks5d -u admin:password123 -u user:pass

# Con puertos específicos
./bin/socks5d -p 1080 -P 8080

# Ayuda completa
./bin/socks5d -h
```

### Cliente de Administración

```bash
# Obtener métricas del servidor
./bin/client -u admin:password123 -m

# Listar usuarios
./bin/client -u admin:password123 -lu

# Ver logs de acceso
./bin/client -u admin:password123 -ll

# Cambiar tamaño de buffer
./bin/client -u admin:password123 -b 8192

# Agregar usuario
./bin/client -u admin:password123 -add newuser:newpass

# Remover usuario
./bin/client -u admin:password123 -rm olduser
```

## Opciones de Configuración

### Servidor (socks5d)

| Opción | Descripción | Valor por Defecto |
|--------|-------------|-------------------|
| `-h` | Muestra ayuda | - |
| `-l <addr>` | Dirección para SOCKS | 127.0.0.1 |
| `-p <port>` | Puerto SOCKS | 1080 |
| `-L <addr>` | Dirección para administración | 127.0.0.1 |
| `-P <port>` | Puerto de administración | 8080 |
| `-u <user:pass>` | Usuario y contraseña (10 usuarios máximo) | - |
| `-v` | Información de versión | - |

### Cliente (client)

| Opción | Descripción |
|--------|-------------|
| `-ip <addr>` | Dirección del servidor |
| `-port <port>` | Puerto de administración |
| `-u <user:pass>` | Credenciales de administrador |
| `-m` | Obtener métricas |
| `-lu` | Listar usuarios |
| `-ll` | Listar logs |
| `-b <size>` | Cambiar tamaño de buffer |
| `-add <user:pass>` | Agregar usuario |
| `-rm <user>` | Remover usuario |

## Protocolo de Administración

### Protocolo HotDogs

Se implementa un protocolo propio llamado "HotDogs" para la administración del servidor, el cual obligatoriamente requiere autenticación. La documentación completa del mismo se encuentra en [doc/HotDogsProtocol.txt](doc/HotDogsProtocol.txt). 

#### Autenticación
```
Cliente -> Servidor: [VER][ULEN][UNAME][PLEN][PASSWD]
Servidor -> Cliente: [VER][STATUS]
```

#### Comandos Disponibles

**RETR (Obtener información)**
- `METRICS`: Estadísticas del servidor
- `LIST_USERS`: Lista de usuarios configurados  
- `LIST_LOGS`: Logs de acceso

**MOD (Modificar configuración)**
- `BUF_SIZE`: Cambiar tamaño de buffer
- `ADD_USER`: Agregar nuevo usuario
- `REMOVE_USER`: Eliminar usuario existente

### Estados de Respuesta
- `SUCCESS_RESPONSE (0)`: Operación exitosa
- `NO_BUN_FOUND (1)`: Método no encontrado
- `BAD_TOPPING (2)`: Opción inválida
- `WHO_LET_BRO_COOK_RESPONSE (3)`: Error general

## Logging y Monitoreo

### Campos del Log
Los logs del protocolo socks5 se encuentran en el archivo `access.log` que se crea al ejecutar el servidor.
- **TIMESTAMP**: Fecha ISO-8601 (UTC)
- **USERNAME**: Usuario que realiza la conexión
- **TYPE**: Siempre 'A' (Access)
- **CLIENT_IP**: IP origen del cliente
- **CLIENT_PORT**: Puerto origen del cliente  
- **DEST_ADDR**: Destino de la conexión
- **DEST_PORT**: Puerto de destino
- **STATUS**: Código SOCKS5 (el 0 es éxito, el resto son errores que se pueden consultar en el RFC 1929 de socks5)

### Métricas Disponibles
- **Conexiones históricas**: Total de conexiones procesadas
- **Conexiones actuales**: Conexiones activas simultáneas
- **Conexiones fallidas**: Total de errores de conexión
- **Bytes transferidos**: Volumen total de datos

## Ejemplos de Uso

### Configuración Básica del Servidor

```bash
# 1. Iniciar servidor con usuarios
./bin/socks5d -u admin:admin123 -u user:userpass

# 2. Verificar que está funcionando
curl -x socks5://user:userpass@localhost:1080 http://httpbin.org/ip
```

### Administración del Servidor

```bash
# Obtener estadísticas
./bin/client -u admin:admin123 -m

# Agregar nuevo usuario
./bin/client -u admin:admin123 -add newuser:newpass

# Verificar que el usuario fue agregado
./bin/client -u admin:admin123 -lu

# Probar el nuevo usuario
curl -x socks5://newuser:newpass@localhost:1080 http://httpbin.org/ip

# Ver logs de acceso
./bin/client -u admin:admin123 -ll
```

---

**Autores**
- Agustin Ronda - 64507
- Tomás Borda - 64517  
- Lautaro Paletta - 64499
- Nicolás Arancibia - 64481

**Protocolos de Comunicación 2025/1 - ITBA**