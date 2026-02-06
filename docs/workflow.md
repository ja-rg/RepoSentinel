## 🧭 Vista: Flujo de Análisis (Wizard)

La interfaz principal de RepoSentinel se presenta como un **wizard multi-step**, guiando al usuario de forma progresiva desde la ingesta del repositorio hasta el reporte final, sin requerir conocimientos avanzados de AppSec.

---

### 🧩 Step 1 — Ingesta del repositorio 📥

**Input**

* URL de repositorio Git **o**
* Archivo ZIP

**Output**

* Repositorio validado y cargado
* Metadata básica (nombre, tamaño, estructura)

**Estados**

* ⏳ Loading: validando acceso / descomprimiendo
* ❌ Error: URL inválida, ZIP corrupto, acceso denegado
* ✅ Success: repositorio listo para análisis

---

### 🧠 Step 2 — Detección de tecnologías

**Input**

* Repositorio cargado (automático)

**Output**

* Stack detectado (Node, Python, C, Docker, etc.)
* Herramientas que se ejecutarán según el stack

**Estados**

* ⏳ Loading: análisis de estructura
* ❌ Error: estructura no reconocida
* ✅ Success: perfil tecnológico confirmado

---

### 🔍 Step 3 — Escaneo de seguridad

**Input**

* Stack detectado
* Configuración por defecto del pipeline

**Output**

* Resultados SAST (Semgrep)
* Resultados SCA (Trivy / Grype)

**Estados**

* ⏳ Loading: herramientas ejecutándose
* ❌ Error: fallo de herramienta / dependencia faltante
* ✅ Success: hallazgos recolectados

---

### 🧠 Step 4 — Correlación y priorización

**Input**

* Resultados crudos de herramientas

**Output**

* Hallazgos normalizados
* Severidad consolidada
* Top riesgos priorizados

**Estados**

* ⏳ Loading: procesando resultados
* ❌ Error: fallo de normalización
* ✅ Success: análisis listo para reporte

---

### 📄 Step 5 — Reporte final

**Input**

* Resultados priorizados

**Output**

* Resumen ejecutivo
* Lista de vulnerabilidades con evidencia
* Exportación (JSON / HTML)

**Estados**

* ⏳ Loading: generando reporte
* ❌ Error: fallo de exportación
* ✅ Success: reporte disponible

---

### 🎯 Principios de la vista

* Progreso visible en todo momento 📊
* Mensajes claros y accionables
* El usuario **nunca decide herramientas**, solo observa resultados
* Cada step es independiente y trazable
