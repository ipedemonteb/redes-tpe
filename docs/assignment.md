# Redes de Información - TP Especial

**2do. Cuatrimestre 2026**

## Objetivo

El objetivo del TP Especial es que cada grupo implemente un componente específico de la arquitectura de una aplicación y muestre su funcionamiento frente al resto de los alumnos y docentes mediante una exposición oral del tema tratado.

Cada grupo deberá implementar, demostrar y explicar, sin excepción, cada uno de los puntos que se especifican a continuación dentro del tema que haya elegido o le haya sido designado por la cátedra cómo mínimo para la aprobación del TP.

## Aplicación

La aplicación es un sitio de comercio en línea llamado The Store compuesta por una serie de microservicios. El código fuente y la documentación se encuentran publicados en el Campus. Se incluye un script para desplegar la aplicación localmente en un clúster de Kubernetes, lo cual sirve para demostrar su despliegue y puede ser utilizado para el desarrollo del TP.

## Temas

Cada grupo deberá implementar solo uno de los siguientes módulos de la arquitectura. Existe la posibilidad de presentar una idea nueva de tema a la cátedra de la materia que deberá ser aprobada para su realización.

La asignación de Temas por grupo sigue la siguiente dinámica: Primero, se va a recibir un comunicado de Campus pidiendo que creen los Grupos en la herramienta Campus. Son grupos de 3 personas. Ahí se va a asignar un número de Grupo.

Luego, se compartirá una planilla donde cada Grupo va a seleccionar su Tema preferido y su Tema alternativo. Va a ser la opción A y la Opción B. No se va a permitir que más de dos grupos elijan el mismo tema ya que necesitamos variedad, en caso de conflicto, la cátedra va a asignar con su propio criterio el tema.

Para el Martes 1 de Septiembre debemos tener los grupos armados y los temas asignados.

A continuación el listado de Temas:

1. Gestión de Infraestructura por Código: Terraform, Pulumi
2. Observabilidad y Monitoreo de Servicios e Infraestructura: Zabbix (Zabbix Server, Zabbix Agent, Zabbix Proxy) o Grafana (Grafana Server, Prometheus, Loki, Tempo)
3. Acceso Remoto Seguro: OpenVPN Community Edition, EasyRSA, OpenVPN-GUI, WireGuard, Tailscale
4. Gestión Centralizada de Logs: ELK (Elasticsearch, Logstash, Kibana) o EFK (Fluentd), Beats, OpenSearch for Elasticsearch
5. Despliegue y Gestión del Cluster de Kubernetes: Ansible, Minikube, kops, K3s, Kind
6. CI/CD para el Despliegue y Gestión de los Servicios: Jenkins, CodePipeline, GitHub Actions o similar, Helm
7. Service Mesh & API Gateway: Kuma, Kong (versión Community)
8. Protección de Servicios con WAF: ModSecurity, Shadow Daemon, OpenWAF
9. Asistente Inteligente de Compras con GenAI: Llama, Ollama, llama.cpp, Spring AI, Qdrant, pgvector

## Consideraciones especiales

- El tipo de diseño y la forma de implementación serán discutidos entre el grupo y la cátedra durante las clases de laboratorio o teóricas, dejando la posibilidad de modificar este enunciado escrito, previo acuerdo entre el docente y los integrantes del grupo.
- Para la evaluación se tendrá en cuenta no sólo la implementación sino también la exposición oral, el documento de pre-entrega y documento final y la implementación del documento estilo "how-to".
- Todos los integrantes del grupo deben estar presentes en la presentación y ser oradores.
- Todos los integrantes deberán ser capaces de responder las preguntas que la cátedra puede hacer durante la presentación.
- Cualquier aclaración oral a cargo de la cátedra con respecto al enunciado del TPE tiene la misma validez que el enunciado escrito.
- La calificación del TPE puede ser diferente para cada miembro del equipo. La cátedra evaluará el nivel de participación individual, pudiendo asignar una nota menor o incluso desaprobar a aquellos estudiantes cuya contribución haya sido insuficiente o nula.
- En cuanto a la temática del trabajo, los estudiantes tienen total libertad para seleccionar el tema que deseen desarrollar. Sin embargo, deben considerar que algunas temáticas podrían implicar costos adicionales para su realización. Los equipos que opten por estos temas asumen la responsabilidad de dichos costos, y esto no podrá ser utilizado como justificación para resultados incompletos o el incumplimiento de las consignas establecidas.

## Pre-entrega

Los alumnos deberán realizar, en equipos, una pre-entrega del Trabajo Práctico Especial (TPE). Esta consistirá en un documento PDF que debe ser conciso, de no más de 4 páginas y debe incluir los siguientes temas y otros que crean necesarios para esta instancia de revisión enfocada en la arquitectura de la solución y definición de POC:

- Problemática y contexto
- Diseño de la solución
- Scope del POC y casos de uso
- Diagrama de arquitectura: deberá especificar con precisión los bloques CIDR, redes IP, sistemas operativos, protocolos y demás detalles técnicos relevantes
- Alternativas consideradas

Este documento de pre-entrega será la base para la evaluación final del trabajo: los equipos deberán implementar exactamente lo que propusieron en este documento. Cualquier equipo que no cumpla al 100% con lo especificado en su pre-entrega deberá recuperar el TPE. Por lo tanto, aunque el proceso de revisión y re-entrega inicial no afecta la calificación, el cumplimiento estricto de lo propuesto es fundamental para aprobar el trabajo.

La cátedra evaluará esta pre-entrega y notificará a los equipos si es necesario agregar más contenido o realizar modificaciones en la propuesta. En caso de que el contenido sea considerado insuficiente, los equipos tendrán una semana adicional para presentar una versión actualizada del documento. Es importante mencionar que este proceso de revisión y potencial re-entrega no tendrá impacto en la calificación final del trabajo.

## Entrega Final

Para la entrega final, los alumnos deberán realizar una presentación de su proyecto con una duración máxima de 30 minutos. En ella, deberán exponer el problema, la solución propuesta, la tecnología adoptada y cualquier otro tema que consideren relevante. Además, es requisito indispensable incluir una demostración funcional del proyecto.

## Material a entregar

Cada grupo deberá subir el siguiente material al Campus en la sección respectiva de su grupo:

- Material de pre-entrega (documento PDF)
- Presentación a utilizar en la exposición (documento PPT)
- Código fuente y documento explicativo (how-to), publicado en GitHub, de cómo se realiza la implementación.

## Fecha de entrega, demostración y exposición oral

- El plazo máximo de pre-entrega del TPE es el Martes 22 de Septiembre a las 23:59 hs vía Campus ITBA.
- La revisión de la pre-entrega del TPE se realizará el Jueves 24 de Septiembre en los horarios de la materia y todos los integrantes deberán estar presentes.
- El plazo máximo de entrega del TP es el Miércoles 4 de Noviembre a las 23:59 hs vía Campus ITBA.
- Las presentaciones de los grupos se realizarán los días Jueves 5 y Martes 10 de Noviembre en los horarios de la materia y según orden aleatorio obtenido mediante sorteo. Cada presentación debe demorar cómo máximo 30 minutos. La presentación es on-line y remota.
- Todos los integrantes del grupo deberán estar presentes en la exposición oral. No se tomarán exposiciones a grupos que no estén presentes todos sus integrantes y considerará desaprobado el TPE en la primera instancia. Siendo la próxima instancia el recuperatorio de TPE.