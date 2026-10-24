# Redes de Información — TP Especial (TPE)
**ITBA — 2do. Cuatrimestre 2026**

> **Estado de Asignación de Grupo:**
> * **Tema Asignado:** **Tema 8 — Protección de Servicios con WAF**
> * **Grupo:** [Completar con N° de Grupo y Miembros]
> * **Stack Tecnológico Sugerido / Enfoque:** ModSecurity (v3 + OWASP Core Rule Set / CRS), Shadow Daemon, Open WAF / Coraza, Ingress-Nginx WAF Controller.

---

## 1. Objetivo General
El objetivo del TP Especial es implementar un componente específico de la arquitectura de una aplicación y demostrar su funcionamiento frente al resto de los alumnos y docentes mediante una exposición oral y técnica.

El grupo deberá implementar, demostrar y explicar, sin excepción, cada uno de los puntos requeridos para el tema asignado (**Tema 8: Protección de Servicios con WAF**) como mínimo indispensable para la aprobación de la materia.

---

## 2. Aplicación Base: *The Store*
* La aplicación de referencia es un sitio de comercio electrónico denominado **The Store**, compuesto por una arquitectura orientada a microservicios.
* El código fuente y la documentación técnica de despliegue se encuentran provistos en el Campus de la cátedra.
* Se incluye un script para desplegar la aplicación localmente en un clúster de **Kubernetes**, el cual servirá como entorno base para implementar e intercalar la capa del WAF.

---

## 3. Tema Asignado: Protección de Servicios con WAF (Tema 8)

### 3.1 Tecnologías y Herramientas Base
* **Motores WAF:** ModSecurity (libmodsecurity v3), Shadow Daemon, Open WAF (o implementaciones modernas compatibles con reglas SecLang / CRS como Coraza).
* **Reglas y Firmas:** OWASP Core Rule Set (CRS v4 / v3.3).
* **Integración Arquitectónica:** Reverse Proxy / API Gateway frontal (ej. Nginx con módulo ModSecurity, Ingress Controller en Kubernetes o contenedor sidecar).

### 3.2 Alcance Técnico y Casos de Uso Esperados
1. **Inspección de Tráfico HTTP/HTTPS:** Capacidad de analizar cabeceras, URI, query params, cookies y el cuerpo (`POST`/`PUT`/`PATCH` con payloads JSON, form-data, etc.).
2. **Mitigación del OWASP Top 10:**
   * Inyección SQL (SQLi).
   * Cross-Site Scripting (XSS).
   * Path Traversal / Local & Remote File Inclusion (LFI/RFI).
   * Remote Code Execution (RCE) y Command Injection.
3. **Modos Operativos:**
   * *Detection Only / Anomaly Scoring:* Registro de eventos sospechosos sin interrupción del tráfico legítimo (calibración para evitar falsos positivos).
   * *Active Blocking:* Bloqueo proactivo con código HTTP 403 Forbidden ante umbrales de anomalía superados o firmas críticas coincidentes.
4. **Auditoría y Trazabilidad:** Logs detallados de transacciones (`audit log`) con correlación de IPs de origen, payload interceptado e identificador de regla (Rule ID).

---

## 4. Estructura de Entregas y Cronograma Crítico

| Hito | Fecha Límite / Día | Modalidad / Formato |
| :--- | :--- | :--- |
| **Pre-entrega** | **Martes 22 de Septiembre — 23:59 hs** | PDF (máximo 4 páginas) vía Campus ITBA |
| **Revisión de Pre-entrega** | **Jueves 24 de Septiembre** | En clase de la materia (asistencia obligatoria) |
| **Entrega Final** | **Miércoles 4 de Noviembre — 23:59 hs** | Código, How-to y PPT vía Campus ITBA |
| **Exposiciones Orales** | **Jueves 5 y Martes 10 de Noviembre** | Exposición remota (máximo 30 min) según sorteo |

---

## 5. Requisitos de la Pre-entrega (POC de WAF)
El documento PDF debe ser conciso (**máximo 4 páginas**) y funcionará como contrato técnico vinculante. Todo lo propuesto deberá estar implementado al 100% en la entrega final.

Debe incluir rigurosamente:
1. **Problemática y Contexto:** Exposición de las superficies de ataque de *The Store* en capa 7 y vectores de riesgo asociados a microservicios expuestos.
2. **Diseño de la Solución:** Topología del WAF (ej. WAF en borde/Ingress vs. WAF como sidecar o proxy inverso dedicado delante de las rutas críticas como autenticación o checkout).
3. **Scope de la POC y Casos de Uso:**
   * Escenarios de tráfico legítimo vs. tráfico anómalo.
   * Ataques específicos a demostrar (ej. inyecciones en endpoints de búsqueda o login).
4. **Diagrama de Arquitectura de Red:**
   * Bloques CIDR y segmentación IP (subredes públicas, privadas o internas del cluster).
   * Sistemas operativos base de los nodos/contenedores.
   * Protocolos, puertos expuestos y certificados TLS.
5. **Alternativas Consideradas:** Justificación de por qué se eligió la combinación tecnológica (ej. ModSecurity + OWASP CRS frente a Shadow Daemon u Open WAF).

---

## 6. Entrega Final y Exposición Oral

### 6.1 Material a Subir al Campus
* **Material de pre-entrega:** Versión PDF aprobada/revisada.
* **Presentación:** Archivo `.ppt` / diapositivas utilizadas en la exposición.
* **Repositorio en GitHub:**
  * Código fuente completo de los manifests, configuraciones del WAF y scripts de automatización.
  * **Documento "How-To":** Guía paso a paso reproducible para clonar, desplegar y poner en marcha el clúster con la protección del WAF y replicar las pruebas de ataque/bloqueo.

### 6.2 Dinámica de la Exposición
* **Tiempo:** 30 minutos cronometrados como máximo.
* **Estructura:** Problema $\rightarrow$ Solución arquitectónica $\rightarrow$ Tecnologías adoptadas $\rightarrow$ **Demostración funcional en vivo (Live Demo)**.
* **Demo requerida:** Enviar requests normales validadas con éxito (200 OK) y disparar payloads maliciosos evidenciando el bloqueo (403 Forbidden) junto con la entrada generada en el log de auditoría del WAF.

---

## 7. Pautas y Consideraciones Especiales de Cátedra
* **Asistencia Total:** Todos los integrantes del grupo deben estar presentes tanto en la revisión de la pre-entrega como en la exposición final, y actuar como oradores activos. La ausencia de un integrante invalida la presentación del grupo y envía al equipo a instancia de recuperatorio.
* **Capacidad de Defensa:** Cada miembro debe poder responder cualquier consulta técnica planteada por la cátedra sobre la arquitectura, el flujo de paquetes y la configuración.
* **Evaluación Individual:** La calificación final puede diferir entre integrantes en función de la participación, compromiso y dominio demostrados.
* **Validez de Aclaraciones:** Toda directiva o ajuste oral realizado por la cátedra durante las clases de teoría o laboratorio tiene el mismo peso y validez que el enunciado formal.