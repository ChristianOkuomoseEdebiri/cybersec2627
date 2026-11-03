# Unidad 1 · Fundamentos de seguridad, criptografía y forense

> **Módulo:** CMO-314 · Ciberseguridad · **RA1** · **Duración:** 20 h · **Peso:** 15 % · **Herramienta:** Python 3 (tipado) + `cryptography`

Esta es la unidad de **cimientos**. Aquí sale por primera vez el patrón que vas a repetir seis veces este curso: **entender el problema → resolverlo con código real → medir que funciona**. Vas a tocar los tres pilares de la seguridad, y las dos disciplinas que sostienen casi todo lo demás: **criptografía** (hash, cifrado, firma, certificados) y **análisis forense**.

!!! tip "Cómo sacarle partido a esta unidad"
    Cada concepto trae **código que puedes ejecutar tú**. Créate una carpeta de pruebas, copia los ejemplos y compruébalos. Al final tienes una buena tanda de **ejercicios con solución** y un **simulacro de examen**: hazlos escribiendo código de verdad, no solo leyendo.

```mermaid
flowchart TB
    A["Principios C·I·D"] --> B["Seguridad física,<br/>ambiental y lógica"]
    A --> R["Amenaza · Vulnerabilidad<br/>Riesgo"]
    A --> C["Criptografía"]
    C --> C1["Hash e integridad"]
    C --> C2["Cifrado simétrico<br/>y asimétrico"]
    C --> C3["Firma y<br/>certificados (PKI)"]
    C1 --> D["Análisis forense<br/>cadena de custodia"]
    C3 --> D
    C1 --> P["Ejercicios<br/>y examen"]
    C2 --> P
    C3 --> P
    D --> P
    style P fill:#dbeafe,color:#1e3a8a,stroke:#3b82f6,stroke-width:3px
    style A fill:#dbeafe,color:#1e3a8a,stroke:#3b82f6,stroke-width:2px
```

**Qué sabrás hacer al terminar:** explicar C·I·D y ampliarlo con autenticidad/trazabilidad · calcular y comparar hashes con criterio · cifrar y descifrar de verdad (simétrico y asimétrico) con `cryptography` · firmar un documento y generar un certificado X.509 · aplicar las fases del análisis forense y la cadena de custodia · escribir Python tipado con CLI profesional, comprobado con `mypy` y `pytest`.

**Cómo se trabaja (aula invertida):** lees la sección y ejecutas los ejemplos antes de clase, con el *reto rápido* intentado → en clase resuelves las actividades en parejas, con ayuda al lado, y preparas el simulacro.

!!! danger "Antes de nada: uso ético y legal"
    Vas a manejar herramientas y técnicas de seguridad. Se usan **solo** sobre tus propios sistemas o el laboratorio autorizado. Manipular sistemas ajenos sin permiso es delito (arts. 197 y 264 del Código Penal). Lee [Uso ético y legal](../recursos/uso-etico.md).

---

## 1. ¿Qué es la seguridad de la información?

Es el conjunto de medidas para proteger datos y servicios frente a accesos, alteraciones o interrupciones no autorizados. No es un producto que se compra: es una propiedad que se **diseña por capas** y se mantiene en el tiempo.

### 1.1 Los tres pilares: C·I·D

| Pilar | Qué garantiza | Se rompe cuando… | La cripto que ayuda |
|---|---|---|---|
| **Confidencialidad** | Solo accede quien está autorizado | Se filtra una base de datos | Cifrado (§5) |
| **Integridad** | La información no se altera sin permiso | Alguien modifica una factura | Hash / firma (§4, §6) |
| **Disponibilidad** | El servicio está accesible cuando se necesita | Un ataque tumba la web | Copias, redundancia |

Se amplían con **autenticidad** (el origen es quien dice ser) y **trazabilidad** (queda registro de quién hizo qué):

```mermaid
flowchart LR
    subgraph "Pilares clásicos"
    Cf["Confidencialidad"]
    In["Integridad"]
    Di["Disponibilidad"]
    end
    subgraph "Ampliación"
    Au["Autenticidad"]
    Tr["Trazabilidad"]
    end
    In -.->|"la firma añade"| Au
    Au -.->|"registrar quién firmó"| Tr
```

Lo modelamos ya con código — nada de listas en abstracto:

```python title="clasificar_incidentes.py"
from dataclasses import dataclass
from enum import Enum

class Pilar(Enum):
    CONFIDENCIALIDAD = "C"
    INTEGRIDAD = "I"
    DISPONIBILIDAD = "D"

@dataclass
class Incidente:
    descripcion: str
    pilar: Pilar

INCIDENTES = [
    Incidente("Ransomware cifra los ficheros del servidor", Pilar.DISPONIBILIDAD),
    Incidente("Un empleado copia la lista de clientes a un USB", Pilar.CONFIDENCIALIDAD),
    Incidente("Cambian el número de cuenta en un albarán", Pilar.INTEGRIDAD),
    Incidente("Un ataque DDoS satura el servidor web", Pilar.DISPONIBILIDAD),
]

for i in INCIDENTES:
    print(f"[{i.pilar.name:16}] {i.descripcion}")
```

```text title="Salida"
[DISPONIBILIDAD ] Ransomware cifra los ficheros del servidor
[CONFIDENCIALIDAD] Un empleado copia la lista de clientes a un USB
[INTEGRIDAD      ] Cambian el número de cuenta en un albarán
[DISPONIBILIDAD  ] Un ataque DDoS satura el servidor web
```

> Usamos `Enum` en vez de cadenas sueltas: así `mypy` **impide** escribir `Pilar.CONFIDENCIALIDA` mal por error. Es una técnica profesional habitual.

!!! reto "Reto rápido 1"
    Un ransomware que además **exfiltra** los datos antes de cifrarlos (doble extorsión, muy habitual en 2025-2026) rompe dos pilares a la vez. ¿Cuáles? Añádelo a `INCIDENTES` con los dos.

### 1.2 Amenaza, vulnerabilidad y riesgo

- **Amenaza:** lo que puede pasar (un incendio, un atacante). Está fuera de tu control.
- **Vulnerabilidad:** la debilidad que lo permite (un servidor sin actualizar). Sí depende de ti.
- **Riesgo:** la combinación de ambos con su impacto. Es lo que se gestiona (a fondo en la UD4).

```mermaid
flowchart LR
    Am["Amenaza<br/>(atacante, incendio…)"] -->|explota| Vu["Vulnerabilidad<br/>(servidor sin parchear)"]
    Vu -->|produce| Ri["Riesgo<br/>= probabilidad × impacto"]
    Ri -->|si se materializa| Inc["Incidente"]
```

```python title="riesgo_simple.py"
def riesgo(probabilidad: float, impacto: float) -> float:
    """probabilidad en [0,1]; impacto en una escala (p. ej. euros o 1-10)."""
    return round(probabilidad * impacto, 2)

# Un servidor sin parchear (vulnerabilidad) frente a un exploit conocido (amenaza)
print(riesgo(probabilidad=0.7, impacto=10))   # alto: la amenaza es muy probable
print(riesgo(probabilidad=0.05, impacto=10))  # bajo: la amenaza es rara
```

```text title="Salida"
7.0
0.5
```

---

## 2. Seguridad física, ambiental y lógica

No toda la seguridad es software: quien entra físicamente a la sala de servidores no necesita romper ningún cifrado.

| Tipo | Protege frente a | Ejemplos |
|---|---|---|
| **Física** | Acceso físico no autorizado | Control de acceso al CPD, cerraduras, cámaras |
| **Ambiental** | El entorno | SAI (batería), climatización, detección de incendios |
| **Lógica** | Usos indebidos del sistema | Contraseñas, permisos, cifrado, cortafuegos, copias |

```python title="clasificar_medida.py"
FISICA = {"camara", "cerradura", "armario", "torniquete", "biometria_entrada"}
AMBIENTAL = {"sai", "climatizacion", "incendios", "humedad", "generador"}

def clasifica(medida: str) -> str:
    if medida in FISICA:
        return "física"
    if medida in AMBIENTAL:
        return "ambiental"
    return "lógica"          # todo lo demás: contraseñas, cifrado, cortafuegos...

for m in ["camara", "sai", "cortafuegos", "cifrado", "mfa"]:
    print(f"{m:12} -> {clasifica(m)}")
```

```text title="Salida"
camara       -> física
sai          -> ambiental
cortafuegos  -> lógica
cifrado      -> lógica
mfa          -> lógica
```

### 2.1 Copias de seguridad: la última línea

La regla **3-2-1**: al menos **3** copias, en **2** soportes distintos, con **1** fuera del sitio. Y **la copia que nunca se ha restaurado no cuenta como copia**: hay que probar la restauración.

```python title="regla_321.py"
from dataclasses import dataclass

@dataclass
class Copia:
    soporte: str        # "disco_local", "nas", "cloud", "cinta"...
    ubicacion: str       # "sitio" o "externo"

def cumple_321(copias: list[Copia]) -> tuple[bool, list[str]]:
    fallos = []
    if len(copias) < 3:
        fallos.append(f"solo hay {len(copias)} copias, hacen falta 3")
    soportes = {c.soporte for c in copias}
    if len(soportes) < 2:
        fallos.append("todas las copias usan el mismo soporte")
    if not any(c.ubicacion == "externo" for c in copias):
        fallos.append("ninguna copia está fuera del sitio")
    return (not fallos, fallos)

copias = [Copia("disco_local", "sitio"), Copia("nas", "sitio")]
print(cumple_321(copias))
```

```text title="Salida"
(False, ['solo hay 2 copias, hacen falta 3', 'ninguna copia está fuera del sitio'])
```

!!! reto "Reto rápido 2"
    Un empleado se lleva un USB con la copia los viernes (soporte: `"usb"`, ubicación: `"externo"`). Añádelo a la lista de arriba junto con una copia en `"cloud"`. ¿Ahora `cumple_321` da `True`?

---

## 3. Python como herramienta de seguridad

Python es tu herramienta durante todo el módulo. Monta el entorno una vez:

```bash title="Preparar el entorno"
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\Activate.ps1
pip install pytest mypy cryptography
```

Escribimos **Python tipado**: las anotaciones documentan y permiten que `mypy` cace errores sin ejecutar nada.

```python title="Tu primera huella digital"
import hashlib

def hash_de_texto(texto: str) -> str:      # (1)!
    """Devuelve el hash SHA-256 de un texto, en hexadecimal."""
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()   # (2)!

print(hash_de_texto("hola"))                # (3)!
print(hash_de_texto("hola"))                # (4)!
```

1.  Las **anotaciones de tipo** (`str -> str`) documentan y permiten que `mypy` detecte errores sin ejecutar.
2.  `.encode("utf-8")` convierte el texto en **bytes**, que es lo que acepta `hashlib`. Olvidarlo es el error clásico.
3.  Imprime `b221d9db…`: 64 caracteres hexadecimales (256 bits).
4.  El mismo texto da **siempre** el mismo hash — lo comprobamos llamando dos veces.

```text title="Salida"
b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79
b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79
```

!!! warning "Atención"
    Muchas funciones devuelven **texto**; para hashear hay que pasar a **bytes** con `.encode()`. Si ves `TypeError: Strings must be encoded before hashing`, es justo esto.

---

## 4. Criptografía I — funciones hash e integridad

Una **función hash** transforma cualquier dato en una huella de longitud fija.

| Propiedad | Qué significa |
|---|---|
| **Determinista** | El mismo dato da siempre el mismo hash |
| **Efecto avalancha** | Cambiar un bit cambia por completo la salida |
| **Unidireccional** | No se puede volver del hash al dato |
| **Resistente a colisiones** | Es inviable encontrar dos datos con el mismo hash |

```mermaid
flowchart LR
    D1["'seguridad'"] --> F["SHA-256"]
    D2["'Seguridad'"] --> F
    F --> H1["1ea9f394… (64 hex)"]
    F --> H2["b64167f5… (64 hex)"]
    H1 -.->|"57 de 64 caracteres distintos"| H2
```

### 4.1 Efecto avalancha, medido con código

```python title="avalancha.py"
import hashlib

def h(t: str) -> str:
    return hashlib.sha256(t.encode()).hexdigest()

def avalancha(a: str, b: str) -> int:
    ha, hb = h(a), h(b)
    return sum(1 for x, y in zip(ha, hb) if x != y)

a, b = "seguridad", "Seguridad"     # solo cambia una letra a mayúscula
print(h(a))
print(h(b))
print(f"Cambian {avalancha(a, b)} de 64 caracteres del hash")
```

```text title="Salida"
1ea9f394f510e2beb43cb0b317258b09bce9f4fccef69407360483690ac9b746
b64167f58e1cf0c322747fbe1a7361084a004ffb5c145fd64e5413ef11215965
Cambian 57 de 64 caracteres del hash
```

> Un cambio mínimo en la entrada altera casi todo el hash: por eso sirve para detectar la más pequeña manipulación.

### 4.2 Elegir el algoritmo (no todos valen)

```python title="comparar_algoritmos.py"
import hashlib

dato = b"documento importante"
for alg in ("md5", "sha1", "sha256", "sha3_256", "blake2b"):
    d = hashlib.new(alg, dato).hexdigest()
    print(f"{alg:9} {len(d)*4:4} bits   {d[:24]}...")
```

```text title="Salida"
md5        128 bits   73943af0696212b0ebfb60cf...
sha1       160 bits   3d8dd0ba48b54b431502c4f6...
sha256     256 bits   dd1cd769ac316412f9a0669e...
sha3_256   256 bits   ce5c2e89bddab0174ba19299...
blake2b    512 bits   e29f58fbe35b5357d889089c...
```

| Algoritmo | Estado | Uso recomendado |
|---|---|---|
| MD5 / SHA-1 | **Rotos** | Nunca para integridad seria |
| **SHA-256** | Vigente, estándar de facto | Integridad, firma, certificados TLS |
| **SHA-3 / BLAKE2** | Vigente, más modernos | Alternativas cuando se busca velocidad o margen extra |

### 4.3 Hash de un fichero grande (por bloques) y comparación segura

```python title="hash_fichero.py"
import hashlib, hmac
from pathlib import Path

def hash_fichero(ruta: Path, algoritmo: str = "sha256") -> str:
    """Hashea leyendo por bloques: funciona igual de bien con 1 KB que con 10 GB."""
    h = hashlib.new(algoritmo)
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(8192), b""):   # 8 KiB por lectura
            h.update(bloque)
    return h.hexdigest()

def integro(esperado: str, actual: str) -> bool:
    """Comparación en tiempo constante: no filtra información por temporización."""
    return hmac.compare_digest(esperado, actual)
```

!!! analogia "Analogía"
    El hash es el **número de precinto** de una caja de pruebas: no dice qué hay dentro, pero si el precinto coincide, nadie la ha abierto.

!!! warning "Hash ≠ cifrado"
    El hash **no se deshace**: no sirve para guardar algo que luego haya que recuperar, sino para **comprobar** que no ha cambiado. Para contraseñas se usa hash **con sal** y funciones lentas (bcrypt, Argon2) — lo verás en la UD4.

!!! reto "Reto rápido 3"
    Ejecuta `avalancha("1234", "1235")`. ¿Cambia también casi todo el hash aunque solo varíe un dígito? ¿Y `avalancha("1234", "1234 ")` (con un espacio al final)?

---

## 5. Criptografía II — cifrado simétrico y asimétrico

Cifrar es transformar un mensaje para que solo lo lea quien tenga la clave.

| | **Simétrico** | **Asimétrico** |
|---|---|---|
| Claves | Una sola, compartida | Par: pública + privada |
| Algoritmos típicos | AES, ChaCha20 (Fernet los usa por debajo) | RSA, curvas elípticas (ECC) |
| Ventaja | Muy rápido | No hay que compartir un secreto |
| Problema | ¿Cómo comparto la clave con seguridad? | Lento para grandes volúmenes |

### 5.1 Simétrico de verdad: Fernet (AES) con `cryptography`

```python title="simetrico_fernet.py"
from cryptography.fernet import Fernet, InvalidToken

clave = Fernet.generate_key()          # ⚠️ guárdala en secreto: cifra y descifra por igual
f = Fernet(clave)

token = f.encrypt(b"numero de cuenta: ES12 3456 7890")
print("Cifrado :", token[:50], b"...")
print("Descifrado:", f.decrypt(token))

# ¿Qué pasa si alguien manipula el mensaje cifrado?
try:
    manipulado = token[:-5] + b"XXXXX"
    f.decrypt(manipulado)
except InvalidToken:
    print("Detectado: el token manipulado NO se puede descifrar")
```

```text title="Salida"
Cifrado : b'gAAAAABo3k9f...' ...
Descifrado: b'numero de cuenta: ES12 3456 7890'
Detectado: el token manipulado NO se puede descifrar
```

> Fernet no solo cifra: también **autentica** el mensaje. Si alguien lo toca, `decrypt` lanza `InvalidToken` en vez de devolver basura silenciosamente. Es cifrado autenticado (AEAD), el estándar profesional.

### 5.2 Asimétrico: RSA (candado público, llave privada)

El problema del cifrado simétrico es el reparto de la clave: si Ana y Luis están lejos, ¿cómo se pasan la clave sin que nadie la intercepte por el camino? El cifrado **asimétrico** lo resuelve con un truco: en vez de **una** clave, cada persona tiene **un par** de claves que funcionan juntas.

- La clave **pública**: se reparte a todo el mundo. **Solo sirve para cifrar.**
- La clave **privada**: se guarda en secreto, no se le da a nadie. **Es la única que descifra** lo que se cifró con su pública.

!!! analogia "La analogía del buzón"
    Imagina un buzón con una ranura. **Cualquiera** puede echar una carta por la ranura (cifrar con la clave pública), pero **solo** quien tiene la llave del buzón (la clave privada) puede abrirlo y leer las cartas. Repartir la "ranura" no es peligroso: con ella solo se puede meter, no sacar.

#### El mecanismo, paso a paso

Cada persona genera su par de claves **una sola vez** y publica su clave pública (en su web, en un servidor de claves, en su perfil…). La privada no sale nunca de su ordenador.

```mermaid
flowchart TB
    subgraph ANA["👩 Ana"]
      AP["🔑 privada de Ana<br/>(secreta)"]
      APub["📢 pública de Ana<br/>(repartida)"]
    end
    subgraph LUIS["👨 Luis"]
      LP["🔑 privada de Luis<br/>(secreta)"]
      LPub["📢 pública de Luis<br/>(repartida)"]
    end
    APub -.->|"Ana reparte su pública"| LUIS
    LPub -.->|"Luis reparte su pública"| ANA
```

Cuando **Ana quiere escribir a Luis**, usa la clave **pública de Luis** para cifrar. A partir de ahí, el mensaje solo se puede abrir con la **privada de Luis** — que solo Luis tiene:

```mermaid
flowchart LR
    M["✉️ Mensaje<br/>de Ana"] -->|"cifra con la<br/>PÚBLICA de Luis"| C["🔒 Cifrado"]
    C -->|"viaja por Internet"| C2["🔒 Cifrado"]
    C2 -->|"descifra con la<br/>PRIVADA de Luis"| M2["✉️ Mensaje<br/>que lee Luis"]
    style C fill:#dbeafe,color:#1e3a8a
    style C2 fill:#dbeafe,color:#1e3a8a
```

> La regla de oro: **se cifra con la clave pública del destinatario.** Fíjate en que la clave pública de *Ana* no interviene para nada cuando Ana **envía**: solo cuando alguien le escribe **a ella**.

#### En Python: 4 scripts que puedes ejecutar tú

Vamos a montar el laboratorio completo con **cuatro scripts independientes**. Cada uno se puede ejecutar por separado porque las claves **se guardan en ficheros** (`.pem`): Luis genera su par una vez, Ana cifra con la pública, Luis descifra con la privada, y una espía lo intenta y fracasa. Créate una carpeta vacía y ve ejecutándolos en orden.

```mermaid
flowchart LR
    G["① generar_claves.py<br/>(Luis)"] --> F1["📄 luis_privada.pem<br/>📄 luis_publica.pem"]
    F1 -->|"Luis reparte<br/>solo la pública"| C["② cifrar.py<br/>(Ana)"]
    C --> M["🔒 mensaje.bin"]
    M --> D["③ descifrar.py<br/>(Luis)"]
    F1 --> D
    M --> E["④ espia.py<br/>(Eva)"]
    style F1 fill:#fef9c3,color:#854d0e
    style M fill:#dbeafe,color:#1e3a8a
```

**① `generar_claves.py`** — Luis genera su par de claves y **guarda las dos** en ficheros. La privada se queda en su ordenador; la pública la repartirá.

```python title="generar_claves.py"
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Guardar la clave PRIVADA (secreta, no se comparte)
Path("luis_privada.pem").write_bytes(privada.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
))

# Guardar la clave PÚBLICA (esta sí se reparte)
Path("luis_publica.pem").write_bytes(privada.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
))

print("Creados: luis_privada.pem (secreta) y luis_publica.pem (para repartir)")
```

```text title="Salida"
Creados: luis_privada.pem (secreta) y luis_publica.pem (para repartir)
```

**② `cifrar.py`** — Ana solo tiene `luis_publica.pem`. Lo carga y cifra su mensaje:

```python title="cifrar.py"
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

publica_luis = serialization.load_pem_public_key(Path("luis_publica.pem").read_bytes())
cifrado = publica_luis.encrypt(b"Hola Luis, nos vemos a las 5", OAEP)
Path("mensaje.bin").write_bytes(cifrado)

print("Mensaje cifrado y guardado en mensaje.bin")
```

```text title="Salida"
Mensaje cifrado y guardado en mensaje.bin
```

**③ `descifrar.py`** — Luis carga su clave **privada** del fichero y abre el mensaje:

```python title="descifrar.py"
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

privada_luis = serialization.load_pem_private_key(Path("luis_privada.pem").read_bytes(), password=None)
mensaje = privada_luis.decrypt(Path("mensaje.bin").read_bytes(), OAEP)

print("Luis lee:", mensaje.decode())
```

```text title="Salida"
Luis lee: Hola Luis, nos vemos a las 5
```

**④ `espia.py`** — Eva ha interceptado `mensaje.bin` y tiene `luis_publica.pem` (es pública). Aun así no puede leer nada: la pública **solo cifra**, y su propia privada no abre un mensaje dirigido a Luis.

```python title="espia.py"
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
cifrado = Path("mensaje.bin").read_bytes()
publica_luis = serialization.load_pem_public_key(Path("luis_publica.pem").read_bytes())

# 1) Una clave pública ni siquiera tiene método para descifrar
print("¿La pública puede descifrar?:", hasattr(publica_luis, "decrypt"))

# 2) Eva prueba con la única privada que tiene (la suya): falla
privada_eva = rsa.generate_private_key(public_exponent=65537, key_size=2048)
try:
    privada_eva.decrypt(cifrado, OAEP)
    print("Eva ha leído el mensaje (esto NO debería pasar)")
except ValueError:
    print("Eva NO puede leer el mensaje: no tiene la privada de Luis")
```

```text title="Salida"
¿La pública puede descifrar?: False
Eva NO puede leer el mensaje: no tiene la privada de Luis
```

> Por eso es seguro repartir la clave pública a cualquiera, incluso publicarla en Internet: con ella **solo** se puede cifrar hacia ti, nunca descifrar lo que va dirigido a ti.

#### ¿Qué es eso de OAEP? ¿Y PSS?

RSA "a secas" es inseguro: cifrar dos veces el mismo mensaje daría el mismo resultado, y eso filtra información. Para evitarlo se añade un **relleno** (*padding*) que mete aleatoriedad antes de aplicar RSA. Hay uno para cada tarea, y **no son intercambiables**:

| Relleno | ¿Para qué? | Dónde lo usas |
|---|---|---|
| **OAEP** | Para **cifrar** (ocultar un mensaje) | `encrypt` / `decrypt` (sección 5.2) |
| **PSS** | Para **firmar** (demostrar autoría) | `sign` / `verify` (sección 6) |

No hace falta que te sepas sus interioridades matemáticas. Lo que tienes que recordar para el examen: **OAEP cifra, PSS firma**, y ambos añaden aleatoriedad para que RSA sea seguro.

**¿El OAEP de descifrar tiene que ser el mismo que el de cifrar?** No el mismo *objeto*, pero **sí la misma configuración**. Quien descifra crea su propio `OAEP`, pero el algoritmo de hash y el `label` tienen que coincidir con los que se usaron al cifrar; si no, falla:

```python title="oaep_debe_coincidir.py"
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
publica = privada.public_key()

oaep_sha256 = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
cifrado = publica.encrypt(b"secreto", oaep_sha256)

# Otro objeto OAEP distinto pero con la MISMA config: funciona
otro_igual = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
print("Misma config (otro objeto):", privada.decrypt(cifrado, otro_igual).decode())

# Config DISTINTA (SHA1 en vez de SHA256): falla
oaep_sha1 = padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
try:
    privada.decrypt(cifrado, oaep_sha1)
except ValueError:
    print("Config distinta (SHA1): no descifra")
```

```text title="Salida"
Misma config (otro objeto): secreto
Config distinta (SHA1): no descifra
```

> Por eso, en todo el proyecto que uses, define el `OAEP` una sola vez (como una constante) y reutilízalo: así cifrado y descifrado usan exactamente la misma configuración sin riesgo de equivocarte.

!!! warning "Lo lento no se cifra con RSA directamente"
    RSA es lento y solo cifra mensajes cortos (más pequeños que la clave). Por eso en la práctica se usa **cifrado híbrido**: se genera una clave simétrica rápida (Fernet/AES), con ella se cifra todo el mensaje, y **solo esa clave corta** se cifra con RSA. Es exactamente lo que hace tu navegador en cada conexión **HTTPS**.

!!! reto "Reto rápido 4"
    Quieres enviar un fichero secreto a una compañera. ¿Con qué clave lo cifras: tu pública, tu privada, la suya pública o la suya privada? ¿Y qué relleno usas, OAEP o PSS?

---

## 6. Criptografía III — firma electrónica y certificados

Cifrar sirve para **ocultar** un mensaje. Firmar sirve para lo contrario: **demostrar que un mensaje es tuyo y que nadie lo ha cambiado**, aunque el mensaje se lea a plena luz. Para ello se usa el par de claves **al revés** que al cifrar:

- Se **firma** con la clave **privada** (solo tú la tienes → solo tú puedes firmar en tu nombre).
- Se **verifica** con la clave **pública** (la tiene todo el mundo → cualquiera puede comprobar que fuiste tú).

Una firma digital da tres garantías a la vez: **autenticidad** (quién lo firmó), **integridad** (no se ha modificado) y **no repudio** (el firmante no puede negar que fue él).

```mermaid
flowchart LR
    D["📄 Documento"] -->|"Ana firma con su<br/>PRIVADA"| F["✍️ Firma"]
    D --> V{"Verificar con la<br/>PÚBLICA de Ana"}
    F --> V
    V -->|coinciden| OK["✅ auténtico<br/>e intacto"]
    V -->|no coinciden| NO["❌ falso o<br/>modificado"]
    style OK fill:#d1fae5,color:#065f46
    style NO fill:#fee2e2,color:#991b1b
```

Para firmar se usa el relleno **PSS** (recuerda de la sección 5.2: **PSS firma**, OAEP cifra). Montamos otro laboratorio con **cuatro scripts independientes**, igual que en el cifrado: Ana genera sus claves, firma un contrato, Luis verifica la firma, y un impostor lo intenta y fracasa. Puedes ejecutarlos tú en orden.

```mermaid
flowchart LR
    G["① generar_claves_ana.py"] --> K["📄 ana_privada.pem<br/>📄 ana_publica.pem"]
    K --> F["② firmar.py<br/>(Ana)"]
    F --> S["📄 contrato.txt<br/>✍️ contrato.sig"]
    S --> V["③ verificar.py<br/>(Luis)"]
    K -->|"solo la pública"| V
    V -->|coinciden| OK["✅ auténtica"]
    V -->|no| NO["❌ falsa o alterada"]
    style K fill:#fef9c3,color:#854d0e
    style OK fill:#d1fae5,color:#065f46
    style NO fill:#fee2e2,color:#991b1b
```

**① `generar_claves_ana.py`** — Ana genera su par de claves y guarda las dos en ficheros:

```python title="generar_claves_ana.py"
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)

Path("ana_privada.pem").write_bytes(privada.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()))

Path("ana_publica.pem").write_bytes(privada.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo))

print("Creados: ana_privada.pem (secreta) y ana_publica.pem (para repartir)")
```

```text title="Salida"
Creados: ana_privada.pem (secreta) y ana_publica.pem (para repartir)
```

**② `firmar.py`** — Ana carga su clave **privada**, firma el contenido del contrato y guarda la firma en `contrato.sig`:

```python title="firmar.py"
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from pathlib import Path

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
privada_ana = serialization.load_pem_private_key(Path("ana_privada.pem").read_bytes(), password=None)

Path("contrato.txt").write_text("Yo, Ana, autorizo el pago de 100 euros")
firma = privada_ana.sign(Path("contrato.txt").read_bytes(), PSS, hashes.SHA256())
Path("contrato.sig").write_bytes(firma)

print(f"Firma creada: contrato.sig ({len(firma)} bytes)")
```

```text title="Salida"
Firma creada: contrato.sig (256 bytes)
```

La firma mide siempre **256 bytes** con una clave de 2048 bits (2048 ÷ 8), da igual que el documento sea una línea o un vídeo entero: se firma el hash del documento, no el documento completo.

**③ `verificar.py`** — Luis solo tiene tres ficheros (`contrato.txt`, `contrato.sig` y `ana_publica.pem`). Carga la pública y comprueba la firma; luego altera el contrato para ver que la verificación falla:

```python title="verificar.py"
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from pathlib import Path

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
publica_ana = serialization.load_pem_public_key(Path("ana_publica.pem").read_bytes())

def firma_valida() -> bool:
    try:
        publica_ana.verify(
            Path("contrato.sig").read_bytes(),    # la firma
            Path("contrato.txt").read_bytes(),     # el documento
            PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False

print("¿Firma válida?:", firma_valida())

# Alguien altera el contrato DESPUÉS de firmarlo (cambia 100 por 900)
Path("contrato.txt").write_text("Yo, Ana, autorizo el pago de 900 euros")
print("Tras cambiar el importe:", firma_valida())
```

```text title="Salida"
¿Firma válida?: True
Tras cambiar el importe: False
```

Cambiar **un solo carácter** (de `100` a `900`) rompe la verificación: integridad y autenticidad en una sola operación. Y como en el cifrado, el **PSS** del que verifica debe tener la **misma configuración** que el del que firmó.

**④ `impostor.py`** — Un impostor firma el mismo contrato con **su propia** clave. Al verificar contra la pública de Ana, se rechaza:

```python title="impostor.py"
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from pathlib import Path

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# El impostor firma con SU clave, no con la de Ana
privada_impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
Path("contrato.txt").write_text("Yo, Ana, autorizo el pago de 100 euros")
firma_falsa = privada_impostor.sign(Path("contrato.txt").read_bytes(), PSS, hashes.SHA256())

# Se verifica contra la PÚBLICA de Ana (del .pem)
publica_ana = serialization.load_pem_public_key(Path("ana_publica.pem").read_bytes())
try:
    publica_ana.verify(firma_falsa, Path("contrato.txt").read_bytes(), PSS, hashes.SHA256())
    print("Firma del impostor aceptada (esto NO debería pasar)")
except InvalidSignature:
    print("Firma del impostor RECHAZADA: no tiene la privada de Ana")
```

```text title="Salida"
Firma del impostor RECHAZADA: no tiene la privada de Ana
```

!!! tip "Cifrar y firmar son simétricos entre sí"
    Fíjate en el patrón: para **cifrar hacia alguien** usas su **pública** (y él descifra con su privada). Para **firmar** usas **tu privada** (y los demás verifican con tu pública). Lo privado es siempre tuyo y nunca sale de tu ordenador; lo público lo reparte su `.pem`.

### 6.1 Certificados digitales: generar uno de verdad

Un **certificado X.509** vincula una clave pública con una identidad. En producción lo firma una **CA** (Autoridad de Certificación); para practicar, generamos uno **autofirmado**:

```python title="certificado_x509.py"
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cmo314.local")])
ahora = datetime.datetime.now(datetime.timezone.utc)

certificado = (
    x509.CertificateBuilder()
    .subject_name(nombre)
    .issuer_name(nombre)                         # autofirmado: emisor = sujeto
    .public_key(clave.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(ahora)
    .not_valid_after(ahora + datetime.timedelta(days=365))
    .sign(clave, hashes.SHA256())
)

print("Sujeto      :", certificado.subject.rfc4514_string())
print("Emisor      :", certificado.issuer.rfc4514_string())
print("Válido hasta:", certificado.not_valid_after_utc.date())
print("Autofirmado :", certificado.subject == certificado.issuer)

pem = certificado.public_bytes(serialization.Encoding.PEM)
print(pem.decode().splitlines()[0])
```

```text title="Salida"
Sujeto      : CN=cmo314.local
Emisor      : CN=cmo314.local
Válido hasta: 2027-09-14
Autofirmado : True
-----BEGIN CERTIFICATE-----
```

Un certificado no vive en una variable: se **guarda como fichero `.pem`** y así es como lo lee un servidor web o un navegador.

```python title="certificado_a_fichero.py"
from pathlib import Path

# Los certificados se distribuyen como ficheros .pem, no en memoria
Path("cert.pem").write_bytes(pem)
print("Certificado guardado en cert.pem")

# Comprobación real: lo recargamos desde el disco, como haría un servidor web
recargado = x509.load_pem_x509_certificate(Path("cert.pem").read_bytes())
print("Mismo sujeto tras recargar del disco:", recargado.subject == certificado.subject)
print("Tamaño del fichero:", Path("cert.pem").stat().st_size, "bytes")
```

```text title="Salida"
Certificado guardado en cert.pem
Mismo sujeto tras recargar del disco: True
Tamaño del fichero: 1005 bytes
```

| Concepto | Qué es |
|---|---|
| **CA (Autoridad de Certificación)** | Entidad de confianza que firma certificados ajenos |
| **Certificado autofirmado** | El emisor y el sujeto son el mismo — vale para pruebas, **no** para producción pública |
| **PKI** | Toda la infraestructura: CAs, certificados, revocación, cadenas de confianza |

!!! reto "Reto rápido 5"
    Si tu navegador visita una web con un certificado **autofirmado**, avisa de "conexión no segura". ¿Por qué, si el cifrado funciona igual de bien?

---

## 7. Análisis forense digital

Investiga un incidente para responder **qué pasó, cómo, cuándo y con qué alcance**, preservando las evidencias para que tengan validez legal.

```mermaid
flowchart LR
    A["1 · Identificación<br/>¿qué ha pasado?"] --> B["2 · Adquisición<br/>copia bit a bit"]
    B --> C["3 · Análisis<br/>sobre la copia"]
    C --> D["4 · Documentación<br/>qué se hizo y cuándo"]
    D --> E["5 · Presentación<br/>informe pericial"]
```

### 7.1 Cadena de custodia, con código

Cuando el perito recibe una prueba (un fichero, un disco, un log), tiene que poder demostrar en el juicio que **no la ha cambiado** mientras la investigaba. La idea es la misma del hash que ya conoces, en tres tiempos: **hash antes → investigar → hash después**. Si los dos hashes coinciden, la prueba está intacta.

Reutilizamos la función `sha256_fichero` de la sección 5:

```python title="forense.py"
import hashlib
from pathlib import Path

def sha256_fichero(ruta: str) -> str:
    return hashlib.sha256(Path(ruta).read_bytes()).hexdigest()

# La prueba que recibe el perito (aquí, un registro del servidor)
Path("prueba.log").write_text("10:03 acceso de root desde 10.0.0.7")

# 1) ANTES de tocar nada: calcula el hash. Es el "precinto" de la prueba.
precinto = sha256_fichero("prueba.log")

# 2) ... el perito analiza la prueba: la lee, la estudia ...

# 3) AL TERMINAR: vuelve a calcular el hash y lo compara con el precinto
if sha256_fichero("prueba.log") == precinto:
    print("La prueba está INTACTA: nadie la ha tocado")
else:
    print("¡ALERTA! La prueba ha sido modificada")
```

```text title="Salida"
La prueba está INTACTA: nadie la ha tocado
```

¿Y si alguien cambia la prueba por el camino? El hash ya no coincide y se detecta al instante:

```python title="forense_manipulada.py"
from pathlib import Path

# El perito guardó el precinto; ahora alguien cambia la IP del atacante en la prueba
Path("prueba.log").write_text("10:03 acceso de root desde 1.2.3.4")

print("¿Sigue intacta?:", sha256_fichero("prueba.log") == precinto)
```

```text title="Salida"
¿Sigue intacta?: False
```

!!! analogia "Analogía"
    El hash de la prueba es su **precinto digital**, como el precinto de una caja de pruebas policial. Se calcula **antes** de tocar nada: si al final sigue igual, has demostrado que no la manipulaste.

!!! info "La cadena de custodia"
    Además del precinto, se apunta **quién** tuvo la prueba y **cuándo** (quién la recogió, quién la copió, quién la analizó). Ese registro se llama **cadena de custodia**, y es lo que da validez a la prueba ante un juez. En código se guardaría como una simple lista de anotaciones con fecha, responsable y acción.

!!! reto "Reto rápido 6"
    ¿Por qué el forense calcula el hash **antes** de empezar a analizar y no después? ¿Qué pasaría con una prueba en un juicio si no lo hiciera?

---

## 8. Errores frecuentes (ten esto a mano)

| Error | Causa | Solución |
|---|---|---|
| `Strings must be encoded before hashing` | Pasar `str` a `hashlib` | `.encode("utf-8")` primero |
| Hashes que "no coinciden" | Espacios, mayúsculas o saltos de línea | Normaliza antes de comparar |
| Comparar hashes/secretos con `==` | Filtra información por tiempos | `hmac.compare_digest(a, b)` |
| Fichero grande lentísimo | Leerlo entero en memoria | Leer por bloques con `update()` |
| Usar MD5 para integridad | Algoritmo roto (colisiones conocidas) | SHA-256 o BLAKE2 |
| `InvalidSignature` inesperado | Verificar con datos distintos a los firmados | Comprueba que pasas el **mismo** `documento` |

---

## 9. Actividades: de lo más sencillo a preguntas tipo examen

Estas actividades nacen de los scripts que ejecutaste en la unidad. Algunas piden que **modifiques algo y observes el resultado**; otras que **pienses** sobre lo que viste.

### Hash e integridad

**1 · 🟢** Ejecutaste `avalancha.py` y viste que cambiar una letra cambiaba casi todo el hash. Ahora predice: ¿los dos hashes de abajo tendrán muchos o pocos caracteres en común?

```python
import hashlib
a = hashlib.sha256("seguridad".encode()).hexdigest()
b = hashlib.sha256("Seguridad".encode()).hexdigest()
print(a == b)
print(a[:8], "...")
print(b[:8], "...")
```

Ejecútalo. ¿Cuántos de los primeros 8 caracteres coinciden? ¿Qué demuestra?

**2 · 🟢** En `hash_fichero.py` calculaste el hash de un fichero. Abre el fichero y cambia **una sola letra**. Vuelve a calcular el hash. ¿Sigue siendo el mismo? ¿Qué propiedad del hash demuestra esto?

**3 · 🟡** El código de `forense.py` guarda un `precinto = sha256_fichero("prueba.log")` antes de analizar el fichero. Luego `forense_manipulada.py` altera el fichero y comprueba `sha256_fichero("prueba.log") == precinto`. ¿Por qué el resultado es `False`? ¿Qué papel juega el hash en una cadena de custodia?

### Cifrado simétrico y asimétrico

**4 · 🟡** En `simetrico_fernet.py` viste que Fernet lanza `InvalidToken` si manipulas el token cifrado. ¿Por qué Fernet puede detectar eso, si solo es un cifrado? ¿Qué significa que sea un cifrado "autenticado"?

**5 · 🟡** En `cifrar.py` cargaste `luis_publica.pem` para cifrar. En `descifrar.py` cargaste `luis_privada.pem` para descifrar. ¿Por qué cifras con la pública y descifras con la privada, y no al revés?

**6 · 🟠** En `espia.py` Eva tiene la clave pública de Luis y el mensaje cifrado, pero no puede leerlo. Explica en tus palabras por qué la clave pública no le sirve para descifrar.

### Firma digital

**7 · 🟡** En `firmar.py` Ana firmó con `ana_privada.pem` y en `verificar.py` Luis verificó con `ana_publica.pem`. ¿Qué ocurrió cuando alteraste `contrato.txt` antes de verificar? ¿Por qué falla la verificación aunque tengas la clave pública correcta?

**8 · 🟠** En `impostor.py` alguien firma con su propia clave privada haciéndose pasar por Ana. Luis verifica con `ana_publica.pem`. ¿Por qué la verificación falla? ¿Qué demuestra esto sobre la utilidad de la firma digital?

### Ejercicios propuestos (sin solución)

**P1 · 🟢** Dado `texto = "mi mensaje secreto"`, calcula su SHA-256 y guárdalo en `precinto`. Luego cambia una letra del texto y comprueba si el nuevo hash es igual al precinto.

**P2 · 🟡** Dado `estado = "open"` (como devuelve nmap para un puerto abierto), escribe un `if` que imprima `"ABIERTO"` si el estado es `"open"` y `"cerrado"` en otro caso.

**P3 · 🟠** Tienes `nvd = {"nginx/1.18.0": "CVE-2021-23017"}` y `banner = "nginx/1.18.0"`. Escribe el código (sin bucles) que imprima el CVE si el banner está en la NVD, y `"sin vulnerabilidades"` si no.

## Cómo se evalúa esta unidad (RA1)

La UT1 y la UT2 forman el **1.er trimestre**, que se evalúa con un **examen tipo test**.

!!! tip "La nota, sin sorpresas"
    **Nota = (aciertos ÷ nº de preguntas) × 10.** Los fallos no restan. Se aprueba con 5.

## Simulacro de examen tipo test

> 20 preguntas. Mezclan teoría y fragmentos de los scripts que ejecutaste. Una sola respuesta correcta.

**1.** ¿Qué imprime este fragmento de `avalancha.py`?

```python
import hashlib
h = lambda t: hashlib.sha256(t.encode()).hexdigest()
print(h("hola") == h("hola"), h("hola") == h("Hola"))
```

- A) `False False`
- B) `True True`
- C) `True False`
- D) `False True`

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: C.</b> El hash es determinista (misma entrada exacta → mismo hash), pero sensible a mayúsculas: "hola" y "Hola" son cadenas distintas y producen hashes distintos.</details>

**2.** El **efecto avalancha** que viste en `avalancha.py` significa que:

- A) El hash crece con el tamaño del fichero
- B) Cambiar un solo carácter de la entrada cambia casi todo el hash
- C) El hash se puede revertir con esfuerzo
- D) Dos entradas distintas pueden dar el mismo hash

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Viste en el lab que "seguridad" y "Seguridad" producen hashes completamente distintos a pesar de diferir solo en una letra.</details>

**3.** En `forense.py` guardaste un `precinto` (el hash del fichero antes de analizarlo). En `forense_manipulada.py` alteraste el fichero. ¿Qué ocurrió al comparar?

- A) El hash siguió siendo el mismo porque el fichero es pequeño
- B) El hash cambió: la comparación devolvió `False`, detectando la alteración
- C) Lanzó una excepción
- D) El hash cambió solo si se alteró más de una línea

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Cualquier cambio en el fichero, por mínimo que sea, produce un hash completamente distinto. El precinto detecta la manipulación.</details>

**4.** ¿Para qué sirve el `precinto` en el análisis forense?

- A) Para cifrar la evidencia
- B) Para demostrar que la evidencia no fue alterada desde que se tomó el hash (cadena de custodia)
- C) Para comprimir el fichero
- D) Para firmar digitalmente el informe

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Si el hash del fichero analizado coincide con el precinto tomado al inicio, nadie lo alteró. Es la base de la cadena de custodia.</details>

**5.** En `simetrico_fernet.py` viste que manipular el token cifrado lanza `InvalidToken`. ¿Por qué?

- A) Porque Fernet solo acepta tokens de 256 bytes exactos
- B) Porque Fernet es cifrado autenticado: verifica la integridad antes de descifrar
- C) Porque la clave era incorrecta
- D) Porque Python detecta los bytes modificados

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Fernet combina cifrado y autenticación (AEAD). Si alguien modifica el texto cifrado, la verificación falla y no se descifra nada.</details>

**6.** En `cifrar.py` cargaste `luis_publica.pem` para cifrar el mensaje. ¿Por qué la clave pública de Luis y no la tuya?

- A) Porque la tuya no está en formato PEM
- B) Porque solo la clave privada de Luis puede descifrar lo que se cifra con su pública
- C) Porque las claves públicas cifran más rápido
- D) Porque es más seguro usar la clave del destinatario

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> En cifrado asimétrico, lo que se cifra con la pública solo se puede descifrar con la privada correspondiente. Es lo que garantiza que solo Luis pueda leer el mensaje.</details>

**7.** En `espia.py`, Eva tiene la clave pública de Luis y el mensaje cifrado. ¿Puede leer el mensaje?

- A) Sí, con la clave pública con la que se cifró
- B) No: descifrar exige la clave privada de Luis, que solo él tiene
- C) Sí, si prueba todas las claves posibles
- D) Solo si el mensaje es corto

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La clave pública solo cifra. Descifrar exige la privada, que nunca se comparte. Eva puede tener la pública y el mensaje cifrado, y seguir sin poder leerlo.</details>

**8.** En `descifrar.py`, al cargar la clave privada usaste `password=None`. ¿Qué significa?

- A) Que la clave es pública
- B) Que el fichero `.pem` no está protegido con contraseña
- C) Que la clave es incorrecta
- D) Que se usa cifrado simétrico

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Las claves privadas en PEM pueden estar protegidas con contraseña. <code>password=None</code> indica que este fichero no la tiene.</details>

**9.** En `firmar.py`, Ana firmó con `PSS` usando su **clave privada**. ¿Qué garantiza esa firma?

- A) Que el mensaje está cifrado
- B) Que fue Ana quien firmó y que el documento no fue alterado después
- C) Que el mensaje llegará íntegro
- D) Que nadie puede leer el documento

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La firma digital garantiza autoría (solo Ana tiene su clave privada) e integridad (cualquier cambio en el documento invalida la firma).</details>

**10.** En `verificar.py` alteraste `contrato.txt` antes de verificar. ¿Qué resultado obtuvo la verificación?

- A) `True`, porque la clave pública era la correcta
- B) `False` / `InvalidSignature`, porque el documento ya no coincide con lo que se firmó
- C) `True`, si el cambio era pequeño
- D) Lanzó `FileNotFoundError`

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La firma se calculó sobre el documento exacto. Cualquier cambio, por mínimo que sea, hace que la verificación falle.</details>

**11.** En `impostor.py`, alguien firma con su propia clave privada y Luis verifica con `ana_publica.pem`. ¿Qué ocurre?

- A) La verificación da `True` porque la firma es válida
- B) La verificación falla: la firma no corresponde a la clave pública de Ana
- C) Se lanza una excepción de fichero no encontrado
- D) Da `True` si el documento es idéntico

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Solo la clave privada de Ana produce firmas que se verifican con su clave pública. Una firma hecha con otra clave privada no pasa la verificación.</details>

**12.** En `generar_claves.py` creaste `luis_privada.pem` y `luis_publica.pem`. ¿Cuál de los dos puede Luis enviar a Ana sin riesgo?

- A) `luis_privada.pem`
- B) `luis_publica.pem`
- C) Ninguno, ambos son secretos
- D) Los dos, son equivalentes

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La clave pública está diseñada para compartirse. La privada nunca se comparte con nadie.</details>

**13.** ¿Qué significa la cabecera `-----BEGIN PRIVATE KEY-----` que viste en los ficheros `.pem`?

- A) Que el fichero contiene una clave pública
- B) Que el fichero contiene una clave privada en formato PEM
- C) Que el fichero está cifrado
- D) Que es un certificado

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Las cabeceras PEM identifican el tipo de contenido. <code>BEGIN PRIVATE KEY</code> indica clave privada; <code>BEGIN PUBLIC KEY</code> indica clave pública.</details>

**14.** En `certificado_x509.py`, el certificado generado tenía `subject == issuer`. ¿Qué tipo de certificado es?

- A) Emitido por una CA reconocida
- B) Autofirmado
- C) Caducado
- D) Revocado

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Cuando el sujeto y el emisor son el mismo, el certificado se firma a sí mismo: es autofirmado. No hay ninguna CA que lo avale.</details>

**15.** ¿Qué diferencia hay entre **OAEP** (usado en `cifrar.py`) y **PSS** (usado en `firmar.py`)?

- A) Son intercambiables
- B) OAEP es el relleno para cifrar con RSA; PSS es el relleno para firmar con RSA
- C) OAEP firma y PSS cifra
- D) Solo se diferencian en el tamaño

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Son dos esquemas de relleno distintos para RSA, cada uno para su operación: OAEP para cifrado, PSS para firma. No son intercambiables.</details>

**16.** ¿Qué ocurriría si usaras **MD5** en vez de SHA-256 para el precinto forense?

- A) Nada, MD5 es igual de seguro
- B) Sería peligroso: MD5 está roto y alguien podría manipular el fichero sin que cambie el hash
- C) El programa sería más rápido y seguro
- D) El hash sería más largo

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> MD5 tiene colisiones conocidas: se pueden crear dos ficheros distintos con el mismo MD5. Un precinto forense basado en MD5 no garantiza integridad.</details>

**17.** La **confidencialidad** (la C del triángulo CID) se rompe cuando:

- A) Un fichero se modifica sin permiso
- B) Alguien no autorizado accede a la información
- C) El servicio deja de estar disponible
- D) Una firma no es válida

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Confidencialidad = que solo acceda quien está autorizado. Se rompe cuando alguien no autorizado lee o copia la información.</details>

**18.** ¿Para qué sirve `hmac.compare_digest(a, b)` en vez de `a == b` para comparar hashes?

- A) Porque `==` no funciona con cadenas hexadecimales largas
- B) Porque `compare_digest` siempre tarda lo mismo, evitando ataques de temporización
- C) Porque `==` lanza una excepción con hashes
- D) No hay diferencia práctica

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> <code>==</code> se detiene en el primer carácter diferente y tarda menos cuantos más caracteres coinciden al principio, lo que filtra información. <code>compare_digest</code> siempre tarda lo mismo.</details>

**19.** Una firma RSA con clave de 2048 bits, ¿de qué tamaño es?

- A) Depende del tamaño del documento firmado
- B) 256 bytes fijos, independientemente del documento
- C) 2048 bytes
- D) 32 bytes (como SHA-256)

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> El tamaño de la firma RSA lo determina el tamaño de la clave (2048 bits = 256 bytes), no el del documento. Viste esto en el lab al medir <code>len(firma)</code>.</details>

**20.** Para verificar la firma de Ana, Luis necesita:

- A) El documento, la firma y la clave **privada** de Ana
- B) El documento, la firma y la clave **pública** de Ana
- C) Solo la firma
- D) El documento y su propia clave privada

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Para verificar hacen falta los tres elementos: el documento original, la firma y la clave pública del firmante. Lo viste en <code>verificar.py</code>.</details>
