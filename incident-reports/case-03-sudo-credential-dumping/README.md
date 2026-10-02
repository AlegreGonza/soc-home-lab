# Caso 03: Abuso de Sudo — Dumping de Credenciales por Permiso Mal Configurado

![Status](https://img.shields.io/badge/status-completed-brightgreen) ![Focus](https://img.shields.io/badge/focus-SOC%20Operations-blue) ![Platform](https://img.shields.io/badge/platform-Linux-orange) ![Telemetry](https://img.shields.io/badge/telemetry-Wazuh%20%2B%20auditd-lightgrey) ![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

---

## Resumen rápido del caso

| Campo | Detalle |
|---|---|
| **Host víctima** | `ubuntu-victima` (192.168.1.46), Ubuntu 26.04 LTS, kernel 7.0.0-31-generic |
| **Usuario comprometido** | `victima` (ya contaba con acceso válido, no-root — continuación del acceso logrado en el Caso 01) |
| **Severidad** | Crítica |
| **Condición inicial** | Usuario de bajo privilegio con un permiso de `sudo` lo suficientemente amplio como para leer cualquier archivo como root |
| **Fuentes de telemetría** | Wazuh (HIDS/SIEM) + `auditd` + `audisp-syslog` (pipeline a medida construido para este caso) |
| **Comportamientos clave** | Enumeración de nivel de privilegios, dumping de credenciales del sistema operativo |
| **Detecciones generadas** | 3 reglas custom de Wazuh (`100030`, `100031`, `100033`) |
| **Caso relacionado** | Caso 04 (escalada de privilegios a root — mismo punto de apoyo, técnica distinta) |

---

## Flujo del ataque

```
Enumeración de privilegios     Dumping de credenciales
(sudo -l)                      (sudo cat /etc/shadow)
     ↓ auditd → audisp-syslog         ↓ decoder de sudo (5402)
   regla 100031                     regla 100030
     ↓                                ↓
             CORRELACIÓN: recon → dump dentro de 5 min
                      regla 100033 (crítica)
```

---

## Contenido

1. [Visión general](#visión-general)
2. [Escenario](#escenario)
3. [Objetivos](#objetivos)
4. [Resumen ejecutivo](#resumen-ejecutivo)
5. [Fuentes de datos](#fuentes-de-datos)
6. [Cronología de eventos](#cronología-de-eventos)
7. [Investigación](#investigación)
8. [Indicadores de compromiso (IOCs)](#indicadores-de-compromiso-iocs)
9. [Indicadores de ataque (IOAs)](#indicadores-de-ataque-ioas)
10. [Mapeo MITRE ATT&CK](#mapeo-mitre-attck)
11. [Severidad del incidente](#severidad-del-incidente)
12. [Acciones de respuesta a incidentes](#acciones-de-respuesta-a-incidentes)
13. [Reglas de detección](#reglas-de-detección)
14. [Conclusión final del incidente](#conclusión-final-del-incidente)
15. [Habilidades demostradas](#habilidades-demostradas)
16. [Disclaimer](#disclaimer)

---

## Visión general

Este caso documenta la primera de dos técnicas de escalada de privilegios post-acceso ejecutadas contra un host donde el atacante ya contaba con acceso válido de bajo privilegio (el mismo punto de apoyo logrado en el Caso 01). Se centra en una mala configuración extremadamente común: un permiso de `sudo` lo suficientemente amplio como para dejar a un usuario no-root leer cualquier archivo del sistema, incluyendo `/etc/shadow`. (El Caso 04 documenta una segunda técnica, independiente, de compromiso total de root vía GTFOBins, sobre el mismo host.)

El uso de `sudo` suele ser o bien totalmente confiado, o bien registrado solo a un nivel genérico y de baja severidad en muchos stacks de SOC. Este caso construye desde cero la capa de detección necesaria para capturar este abuso específico, cerrando ese punto ciego.

## Escenario

- **Host víctima**: `ubuntu-victima`, Ubuntu 26.04 LTS, kernel `7.0.0-31-generic`, IP `192.168.1.46`.
- **Manager de Wazuh**: contenedor Docker (`single-node-wazuh.manager-1`, deploy `wazuh-docker/single-node`) en una PC Windows separada.
- **Usuario comprometido**: `victima`, con un permiso de `sudo` lo suficientemente amplio como para leer cualquier archivo como root.
- **Condición inicial**: acceso por shell ya obtenido (continuación del punto de apoyo del Caso 01).
- **Detalle relevante del entorno**: el `sudo` de este build es `sudo-rs` (la reimplementación en Rust, versión 0.2.13), no el `sudo` clásico en C — una base de código y un esquema de versionado completamente distintos, con consecuencias directas sobre cómo hay que auditarlo (ver Investigación).

## Objetivos

1. Medir cuánto de una secuencia de dumping de credenciales vía `sudo` captura el pipeline estándar de Wazuh/`auth.log`, y cuánto requiere ingeniería a medida.
2. Construir visibilidad a nivel de host sobre los argumentos de los comandos `sudo`, independiente del logging (insuficiente) propio de `sudo-rs`.
3. Correlacionar el patrón de dos pasos —reconocimiento de privilegios, seguido de acceso a credenciales— en una sola alerta de alta confianza.

## Resumen ejecutivo

El atacante primero enumeró sus propios privilegios de `sudo` (`sudo -l`), y luego usó ese mismo acceso para volcar `/etc/shadow`. Ninguno de los dos pasos era confiablemente visible a través del pipeline de logging estándar, así que se construyó un pipeline a medida `auditd → audisp-syslog → Wazuh` específicamente para capturar los argumentos completos de línea de comandos de las invocaciones de `sudo`. Luego se construyó una regla de correlación para escalar el patrón de dos pasos —recon seguido de dumping dentro de 5 minutos— de dos eventos de severidad baja/media a una sola alerta crítica, ya que ningún evento aislado es un indicador confiable (los administradores ejecutan `sudo -l` y `sudo cat` de forma rutinaria), pero la secuencia específica sí lo es.

La severidad se clasifica como **Crítica**: el archivo volcado expone el hash de contraseña de cada cuenta local para cracking offline, a partir de una única mala configuración específica de `sudo`.

## Fuentes de datos

| Fuente | Qué aporta |
|---|---|
| `auditd` (watch custom de execve sobre `sudo`, persistido en `/etc/audit/rules.d/`) | Visibilidad completa de línea de comandos para invocaciones de `sudo`, independiente del logging propio de `sudo-rs` |
| `audisp-syslog` | Convierte los registros multilínea `EXECVE` de auditd en entradas syslog de una sola línea, que Wazuh ingiere vía su `localfile` de formato `syslog` ya existente |
| Wazuh — decoder de sudo (regla `5402`) | Detección nativa genérica de "sudo exitoso a root" — genérica, baja severidad, insuficiente por sí sola |
| Wazuh — reglas custom `100030`/`100031`/`100033` | Detección construida a medida para este caso, validada con `wazuh-logtest` y tráfico en vivo |

## Cronología de eventos

| Evento | rule.id | Nivel |
|---|---|---|
| Recon: `sudo -l` (enumeración de privilegios) | `100031` | 3 |
| `sudo cat /etc/shadow` (dumping de credenciales) | `100030` | 12 |
| **Correlación**: recon → dump dentro de 300s | `100033` | 13 |

## Investigación

El logging propio de `sudo-rs` (`/var/log/auth.log`) resultó insuficiente para capturar de forma confiable los argumentos completos de línea de comandos necesarios para la correlación, así que se construyó un watch de execve de `auditd` a medida, persistido a través de reinicios:

```bash
echo '-a always,exit -F arch=b64 -S execve -F exe=/usr/lib/cargo/bin/sudo -k sudo_correct' \
  | sudo tee /etc/audit/rules.d/sudo_correct.rules
sudo augenrules --load
```

Notar la ruta del ejecutable: `/usr/lib/cargo/bin/sudo`, no `/usr/bin/sudo`. Este build usa `sudo-rs` (la reimplementación en Rust de sudo, versión 0.2.13 — una base de código y esquema de versionado completamente distinto al `sudo` clásico en C 1.9.x), y auditar la ruta incorrecta produce silenciosamente cero eventos.

`audisp-syslog` reenvía estos registros a `/var/log/syslog`, que Wazuh ya lee vía un `localfile` de formato `syslog` existente — no hizo falta registrar una fuente de log nueva.

Se resolvieron dos problemas de ingeniería construyendo este pipeline:
- Wazuh rechaza `frequency="1"` (`Invalid frequency: 1. Must be higher than 1 and lower than 10000.`) — la regla de correlación (`100033`) se escribió con `frequency="2"`.
- La regla `100031` (la regla de recon de `sudo -l`) falló en matchear silenciosamente durante un buen tiempo, pese a muchos intentos de regex. La causa raíz final: **los caracteres de comilla doble literales dentro de un bloque `<match type="pcre2">` provocan fallos de match silenciosos en este entorno**, incluso escapados (`\"`) o como entidad (`&quot;`). La solución fue evitar por completo los caracteres de comilla y matchear sobre substrings posicionales sin comillas (`EXECVE.*argc=2.*sudo.*-l`) — un patrón que el trabajo de detección posterior en este host (Caso 04) también sigue.

Ambas reglas se confirmaron disparando en secuencia contra actividad real de `sudo -l` → `sudo cat /etc/shadow`, con la regla de correlación (`100033`) escalando el par a severidad crítica.

## Indicadores de compromiso (IOCs)

| Tipo | Valor | Contexto |
|---|---|---|
| Usuario comprometido | `victima` | Cuenta de bajo privilegio con un permiso de `sudo` lo suficientemente amplio como para leer cualquier archivo |
| Archivo de credenciales volcado | `/etc/shadow` | Leído vía `sudo cat` |
| Implementación de `sudo` | `sudo-rs` 0.2.13 (`/usr/lib/cargo/bin/sudo`) | Reimplementación en Rust, no el sudo clásico |

## Indicadores de ataque (IOAs)

| Comportamiento | Por qué es sospechoso |
|---|---|
| `sudo -l` inmediatamente seguido de `sudo cat /etc/shadow` en cuestión de minutos | Enumeración de privilegios seguida directamente de acceso a credenciales — no es la secuencia típica del trabajo administrativo rutinario |

## Mapeo MITRE ATT&CK

| Fase | Técnica | ID | Táctica | Evidencia | Confianza |
|---|---|---|---|---|---|
| Descubrimiento de privilegios | Permission Groups Discovery | T1069.001 | Discovery | Regla `100031` (`sudo -l`) | Alta |
| Acceso a credenciales | OS Credential Dumping | T1003.008 | Credential Access | Regla `100030` (lectura de `/etc/shadow`) | Alta |
| Cadena compuesta | Recon → Dumping de credenciales | T1069.001 → T1003.008 | Discovery → Credential Access | Regla `100033` (correlación) | Alta |

## Severidad del incidente

**Clasificación: Crítica.**

Justificación: el archivo volcado expone el hash de contraseña de cada cuenta local para cracking offline — una única mala configuración de `sudo` con impacto de exposición de credenciales a nivel de todo el sistema, no limitado a la cuenta comprometida.

## Acciones de respuesta a incidentes

1. **Contención**: contención reversible (revocar el permiso específico de `sudo`, forzar el cierre de la sesión) más escalamiento inmediato al equipo de IR — un evento de dumping de credenciales puede indicar que la cuenta en sí está totalmente comprometida y amerita investigación de causa raíz, no aislamiento total automático a nivel Tier 1.
2. **Preservación de evidencia**: exportar los eventos `rule.id: 100030, 100031, 100033` y los registros crudos de `auditd`/`audisp-syslog` antes de la rotación de logs.
3. **Erradicación**: auditar y ajustar el permiso de `sudoers` para `victima` — acotar el acceso de lectura de archivos de forma explícita en vez de otorgar permisos amplios de `sudo`.
4. **Recuperación**: rotar las contraseñas de todas las cuentas locales — el dump de `/etc/shadow` debe tratarse como si cada hash estuviera ahora sujeto a cracking offline, sin importar la fortaleza individual de cada contraseña.
5. **Post-incidente**: formalizar un proceso de revisión de `sudoers` para cualquier permiso lo suficientemente amplio como para leer archivos arbitrarios.

## Reglas de detección

```xml
<group name="local,recon_sudo,">
<rule id="100031" level="3">
  <match type="pcre2">EXECVE.*argc=2.*sudo.*-l</match>
  <description>Sudo privilege recon (sudo -l)</description>
  <mitre><id>T1069.001</id></mitre>
</rule>
</group>

<rule id="100030" level="12">
  <if_sid>5402</if_sid>
  <match>/etc/shadow|/etc/passwd</match>
  <description>Credential dumping via sudo</description>
  <mitre><id>T1003.008</id></mitre>
</rule>

<group name="local,credential_dump_chain,">
<rule id="100033" level="13" frequency="2" timeframe="300">
  <if_sid>5402</if_sid>
  <if_matched_group>recon_sudo</if_matched_group>
  <match>/etc/shadow|/etc/passwd</match>
  <description>Full attack chain: recon followed by credential dumping</description>
  <mitre><id>T1069.001</id><id>T1003.008</id></mitre>
</rule>
</group>
```
*Validado* con `wazuh-logtest` y tráfico en vivo: una secuencia real `sudo -l` → `sudo cat /etc/shadow` disparó `100031`, luego `100030`, luego `100033`, en orden.

**Versión agnóstica de SIEM**: convertida a formato **Sigma** — ver [`detection-rules/sigma/`](detection-rules/sigma/).

## Conclusión final del incidente

Este caso demuestra cómo una mala configuración de `sudo` común y fácil de pasar por alto (un permiso de lectura de archivos más amplio de lo pretendido) habilita el dumping completo de credenciales, y cómo cerrar el punto ciego de visibilidad resultante requirió construir un pipeline a medida basado en `auditd` en vez de confiar en el logging propio de `sudo`. La regla de correlación construida acá —escalando dos eventos individualmente ambiguos a una sola alerta de alta confianza en base a secuencia y tiempo— es el mismo patrón de diseño reutilizado y extendido en el Caso 04.

## Habilidades demostradas

- Construcción desde cero de un pipeline de visibilidad `auditd → audisp-syslog → Wazuh` a medida, incluyendo persistencia a través de reinicios
- Diagnóstico de la causa raíz de un fallo de detección silencioso a nivel del motor (un bug de caracteres de comilla en `pcre2`) mediante pruebas sistemáticas y reproducibles
- Diseño de una regla de correlación que convierte dos eventos de baja confianza en una sola alerta de alta confianza en base a secuencia y tiempo
- Adaptación de la ingeniería de detección a una implementación no estándar de `sudo` (`sudo-rs`), verificando la ruta real del binario en vez de asumir los valores por defecto de GNU/Linux clásico
- Mapeo de evidencia técnica a MITRE ATT&CK con niveles de confianza explícitos

## Disclaimer

Este es un incidente **real, ejecutado deliberadamente** en un home lab aislado, con fines educativos y de portafolio. Ninguna de las máquinas o datos involucrados pertenece a un tercero ni a un entorno de producción.
