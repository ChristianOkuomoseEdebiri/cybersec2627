# Unidad 3 · Seguridad perimetral y acceso remoto

| | |
|---|---|
| **Resultado de aprendizaje** | RA3 · Implanta seguridad perimetral y acceso remoto |
| **Trimestre** | 2.º |
| **Duración** | 14 horas |
| **Herramientas** | Docker Compose · FastAPI · Nginx · `curl` · SSH |

El **perímetro** de una red es su frontera con el exterior. Esta unidad trata de cómo se protege esa frontera (cortafuegos, DMZ, segmentación) y de cómo se permite el **acceso remoto seguro** (protocolos cifrados, pasarelas, VPN). La teoría es breve y va directa a la práctica: construirás **un único laboratorio** que monta la intranet de una empresa pequeña, con una API privada detrás de una pasarela, y comprobarás tú mismo por qué está protegida.

!!! info "Esta unidad se evalúa con test"
    El laboratorio es la forma de **entender** los conceptos montándolos. La calificación es un **examen tipo test**; al final tienes un simulacro.

```mermaid
flowchart LR
    T["Teoría breve<br/>perímetro · protocolos · VPN · AAA"] --> L["🧪 Laboratorio único<br/>intranet con FastAPI + Nginx + HTTPS"]
    L --> S["📝 Simulacro de test"]
    style L fill:#d1fae5,color:#065f46,stroke:#10b981,stroke-width:2px
    style S fill:#dbeafe,color:#1e3a8a,stroke:#3b82f6,stroke-width:2px
```

## Parte 1 · Teoría

### 1.1 Seguridad perimetral: Internet, red interna y DMZ

Imagina una empresa como un edificio. **Internet** es la calle; la **red interna (LAN)** son las oficinas privadas donde está lo valioso (bases de datos, ficheros); y la **DMZ** (*zona desmilitarizada*) es como la **recepción**: una zona intermedia donde se atiende al público sin dejarle entrar en las oficinas.

<figure>

<svg width="100%" viewBox="0 0 680 420" role="img" xmlns="http://www.w3.org/2000/svg">
<title>Arquitectura DMZ al estilo Cisco</title>
<desc>Diagrama de seguridad perimetral: Internet, cortafuegos exterior, DMZ con servidores públicos, cortafuegos interior y red interna LAN</desc>
<defs><marker id="ard" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>
<rect x="10" y="30" width="110" height="360" rx="10" fill="none" stroke="#E24B4A" stroke-width="1.5" stroke-dasharray="6 3"/>
<text font-size="12" font-family="sans-serif" x="65" y="52" text-anchor="middle" fill="#A32D2D" font-weight="500">Internet</text>
<ellipse cx="65" cy="130" rx="38" ry="26" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<ellipse cx="45" cy="120" rx="20" ry="13" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<ellipse cx="82" cy="118" rx="22" ry="14" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="65" y="134" text-anchor="middle" fill="#A32D2D">internet</text>
<rect x="30" y="228" width="70" height="36" rx="6" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="65" y="250" text-anchor="middle" fill="#A32D2D">atacante</text>
<rect x="30" y="296" width="70" height="36" rx="6" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="65" y="318" text-anchor="middle" fill="#A32D2D">usuario ext.</text>
<rect x="145" y="155" width="50" height="88" rx="8" fill="#FAC775" stroke="#BA7517" stroke-width="1.5"/>
<text font-size="11" font-family="sans-serif" x="170" y="178" text-anchor="middle" fill="#633806" font-weight="500">🔥 FW</text>
<text font-size="10" font-family="sans-serif" x="170" y="192" text-anchor="middle" fill="#633806">exterior</text>
<text font-size="10" font-family="sans-serif" x="170" y="206" text-anchor="middle" fill="#633806">filtrado</text>
<text font-size="10" font-family="sans-serif" x="170" y="220" text-anchor="middle" fill="#633806">básico</text>
<line x1="122" y1="195" x2="143" y2="195" stroke="#E24B4A" stroke-width="1.5" marker-end="url(#ard)"/>
<text font-size="10" font-family="sans-serif" x="132" y="188" text-anchor="middle" fill="#A32D2D">HTTP</text>
<text font-size="10" font-family="sans-serif" x="132" y="207" text-anchor="middle" fill="#A32D2D">HTTPS</text>
<rect x="208" y="30" width="195" height="360" rx="10" fill="#E1F5EE" stroke="#0F6E56" stroke-width="1.5" stroke-dasharray="6 3"/>
<text font-size="12" font-family="sans-serif" x="305" y="52" text-anchor="middle" fill="#085041" font-weight="500">DMZ · Zona perimetral</text>
<rect x="228" y="68" width="155" height="50" rx="6" fill="#9FE1CB" stroke="#0F6E56" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="305" y="90" text-anchor="middle" fill="#04342C" font-weight="500">🌐 Servidor web</text>
<text font-size="10" font-family="sans-serif" x="305" y="108" text-anchor="middle" fill="#085041">Nginx / Apache</text>
<rect x="228" y="140" width="155" height="50" rx="6" fill="#9FE1CB" stroke="#0F6E56" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="305" y="162" text-anchor="middle" fill="#04342C" font-weight="500">✉️ Servidor correo</text>
<text font-size="10" font-family="sans-serif" x="305" y="180" text-anchor="middle" fill="#085041">SMTP / IMAP</text>
<rect x="228" y="212" width="155" height="50" rx="6" fill="#9FE1CB" stroke="#0F6E56" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="305" y="234" text-anchor="middle" fill="#04342C" font-weight="500">⚙️ Proxy / Pasarela</text>
<text font-size="10" font-family="sans-serif" x="305" y="252" text-anchor="middle" fill="#085041">como el Nginx del lab</text>
<rect x="228" y="284" width="155" height="50" rx="6" fill="#9FE1CB" stroke="#0F6E56" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="305" y="306" text-anchor="middle" fill="#04342C" font-weight="500">🔎 DNS público</text>
<text font-size="10" font-family="sans-serif" x="305" y="324" text-anchor="middle" fill="#085041">resolución de nombres</text>
<line x1="197" y1="195" x2="226" y2="195" stroke="#0F6E56" stroke-width="1.5" marker-end="url(#ard)"/>
<text font-size="10" font-family="sans-serif" x="212" y="188" text-anchor="middle" fill="#085041">solo</text>
<text font-size="10" font-family="sans-serif" x="212" y="207" text-anchor="middle" fill="#085041">80/443</text>
<rect x="418" y="155" width="50" height="88" rx="8" fill="#FAC775" stroke="#BA7517" stroke-width="1.5"/>
<text font-size="11" font-family="sans-serif" x="443" y="178" text-anchor="middle" fill="#633806" font-weight="500">🔥 FW</text>
<text font-size="10" font-family="sans-serif" x="443" y="192" text-anchor="middle" fill="#633806">interior</text>
<text font-size="10" font-family="sans-serif" x="443" y="206" text-anchor="middle" fill="#633806">filtrado</text>
<text font-size="10" font-family="sans-serif" x="443" y="220" text-anchor="middle" fill="#633806">estricto</text>
<line x1="405" y1="195" x2="416" y2="195" stroke="#0F6E56" stroke-width="1.5" marker-end="url(#ard)"/>
<rect x="480" y="30" width="185" height="360" rx="10" fill="#E6F1FB" stroke="#185FA5" stroke-width="1.5" stroke-dasharray="6 3"/>
<text font-size="12" font-family="sans-serif" x="572" y="52" text-anchor="middle" fill="#0C447C" font-weight="500">Red interna · LAN</text>
<line x1="471" y1="195" x2="478" y2="195" stroke="#185FA5" stroke-width="1.5" marker-end="url(#ard)"/>
<rect x="498" y="68" width="148" height="50" rx="6" fill="#B5D4F4" stroke="#185FA5" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="572" y="90" text-anchor="middle" fill="#042C53" font-weight="500">💻 PCs empleados</text>
<text font-size="10" font-family="sans-serif" x="572" y="108" text-anchor="middle" fill="#0C447C">acceso interno</text>
<rect x="498" y="140" width="148" height="50" rx="6" fill="#B5D4F4" stroke="#185FA5" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="572" y="162" text-anchor="middle" fill="#042C53" font-weight="500">🗄 Base de datos</text>
<text font-size="10" font-family="sans-serif" x="572" y="180" text-anchor="middle" fill="#0C447C">nunca expuesta</text>
<rect x="498" y="212" width="148" height="50" rx="6" fill="#B5D4F4" stroke="#185FA5" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="572" y="234" text-anchor="middle" fill="#042C53" font-weight="500">⚙️ API interna</text>
<text font-size="10" font-family="sans-serif" x="572" y="252" text-anchor="middle" fill="#0C447C">como en el lab</text>
<rect x="498" y="284" width="148" height="50" rx="6" fill="#B5D4F4" stroke="#185FA5" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="572" y="306" text-anchor="middle" fill="#042C53" font-weight="500">🔑 RADIUS / AAA</text>
<text font-size="10" font-family="sans-serif" x="572" y="324" text-anchor="middle" fill="#0C447C">autenticación central</text>
<rect x="22" y="388" width="12" height="10" rx="2" fill="none" stroke="#E24B4A" stroke-dasharray="4 2" stroke-width="1.5"/>
<text font-size="11" font-family="sans-serif" x="40" y="397" fill="#A32D2D">No confiable</text>
<rect x="140" y="388" width="12" height="10" rx="2" fill="none" stroke="#0F6E56" stroke-dasharray="4 2" stroke-width="1.5"/>
<text font-size="11" font-family="sans-serif" x="158" y="397" fill="#085041">DMZ</text>
<rect x="210" y="388" width="12" height="10" rx="2" fill="none" stroke="#185FA5" stroke-dasharray="4 2" stroke-width="1.5"/>
<text font-size="11" font-family="sans-serif" x="228" y="397" fill="#0C447C">Red interna</text>
<rect x="358" y="388" width="12" height="10" rx="6" fill="#FAC775" stroke="#BA7517" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="376" y="397" fill="#633806">Cortafuegos</text>
</svg>

<figcaption>Arquitectura clásica con DMZ: dos cortafuegos crean tres zonas con distinto nivel de confianza. En el laboratorio replicas esto con las redes Docker <code>dmz</code> e <code>interna</code>.</figcaption>
</figure>

La regla de oro: **desde Internet nunca se llega directamente a la red interna**. Lo que da la cara (una web, una pasarela) vive en la DMZ; si alguien la compromete, todavía tiene otra barrera antes de llegar a lo importante.

- **Cortafuegos (firewall):** el portero que decide qué tráfico pasa, según reglas.
- **Segmentación de redes:** dividir la red en zonas aisladas, de modo que un problema en una no contamine las demás. Es lo que harás con las dos redes Docker del laboratorio.

#### Puertos TCP: las puertas del servidor

Imagina el servidor como un edificio con **65 535 puertas numeradas**. Cada servicio escucha detrás de una puerta concreta y espera que alguien llame. Cuando tu navegador escribe `https://servidor`, llama siempre a la puerta **443** porque HTTPS tiene ese número asignado por convenio internacional.

```
Puerto  Servicio         ¿Lo viste en el curso?
──────  ───────────────  ──────────────────────
   22   SSH              UT3 · acceso remoto cifrado
   80   HTTP             UT3 · Nginx recibe y redirige a 443
  443   HTTPS            UT3 · Nginx con TLS (lab: puerto 8443)
 3306   MySQL/MariaDB    UT2 · nmap lo escaneó en el Lab 2
 8000   API del lab      UT3 · FastAPI, solo accesible desde la red interna
 8443   HTTPS del lab    UT3 · puerto no estándar para no necesitar root
```

Tres estados posibles cuando nmap (o `curl`) intenta conectarse a un puerto:

| Estado | Qué significa | Ejemplo en el curso |
|---|---|---|
| **open** | Hay un servicio escuchando | Puerto 80 en el Lab 2 de UT2 |
| **closed** | El sistema responde pero nadie escucha → *Connection refused* | Puertos 22, 443… en el Lab 2 |
| **filtered** | Un firewall descarta el paquete sin responder | Lo que hace el FW exterior en la DMZ |

La regla de oro para un administrador: **cuantos menos puertos abiertos, menor es la superficie de ataque**. Cada puerta abierta es una que un atacante puede intentar cruzar.

!!! tip "Puertos no estándar"
    En el laboratorio usamos el **8443** en vez del 443 y el **8080** en vez del 80. Los puertos por debajo del 1024 requieren permisos de administrador (root) para usarlos. En desarrollo se usan puertos altos para no necesitar sudo.

Pulsa cada puerta para ver qué hay detrás y cómo aparece en el laboratorio:

<div style="border:1px solid var(--md-default-fg-color--lightest);border-radius:8px;overflow:hidden;margin:1rem 0">
<svg width="100%" viewBox="0 0 680 310" role="img" xmlns="http://www.w3.org/2000/svg" id="puertos-svg">
<title>Puertos TCP como puertas de un servidor</title>
<desc>Edificio interactivo: pulsa cada puerta numerada para ver qué servicio escucha detrás</desc>
<rect x="160" y="10" width="360" height="220" rx="12" fill="#E6F1FB" stroke="#185FA5" stroke-width="1.5"/>
<rect x="160" y="10" width="360" height="34" rx="12" fill="#185FA5"/>
<rect x="160" y="30" width="360" height="14" fill="#185FA5"/>
<text font-size="13" font-family="sans-serif" x="340" y="32" text-anchor="middle" fill="#E6F1FB" font-weight="500">Servidor (IP: 10.0.0.1) · 65 535 puertas</text>
<g id="pb22" style="cursor:pointer" onclick="mostrar(22)">
  <rect x="182" y="58" width="88" height="68" rx="6" fill="#9FE1CB" stroke="#0F6E56" stroke-width="1.5"/>
  <rect x="210" y="76" width="30" height="38" rx="4" fill="#0F6E56" opacity=".3"/>
  <circle cx="236" cy="97" r="3" fill="#0F6E56"/>
  <text font-size="13" font-family="sans-serif" x="226" y="72" text-anchor="middle" fill="#04342C" font-weight="500">:22</text>
  <text font-size="11" font-family="sans-serif" x="226" y="138" text-anchor="middle" fill="#085041">SSH</text>
</g>
<g id="pb80" style="cursor:pointer" onclick="mostrar(80)">
  <rect x="296" y="58" width="88" height="68" rx="6" fill="#B5D4F4" stroke="#185FA5" stroke-width="1.5"/>
  <rect x="324" y="76" width="30" height="38" rx="4" fill="#185FA5" opacity=".3"/>
  <circle cx="350" cy="97" r="3" fill="#185FA5"/>
  <text font-size="13" font-family="sans-serif" x="340" y="72" text-anchor="middle" fill="#042C53" font-weight="500">:80</text>
  <text font-size="11" font-family="sans-serif" x="340" y="138" text-anchor="middle" fill="#0C447C">HTTP</text>
</g>
<g id="pb443" style="cursor:pointer" onclick="mostrar(443)">
  <rect x="410" y="58" width="88" height="68" rx="6" fill="#EEEDFE" stroke="#534AB7" stroke-width="1.5"/>
  <rect x="438" y="76" width="30" height="38" rx="4" fill="#534AB7" opacity=".3"/>
  <circle cx="464" cy="97" r="3" fill="#534AB7"/>
  <text font-size="13" font-family="sans-serif" x="454" y="72" text-anchor="middle" fill="#26215C" font-weight="500">:443</text>
  <text font-size="11" font-family="sans-serif" x="454" y="138" text-anchor="middle" fill="#3C3489">HTTPS</text>
</g>
<g id="pb8000" style="cursor:pointer" onclick="mostrar(8000)">
  <rect x="182" y="158" width="88" height="68" rx="6" fill="#FAC775" stroke="#BA7517" stroke-width="1.5"/>
  <rect x="210" y="176" width="30" height="38" rx="4" fill="#BA7517" opacity=".3"/>
  <circle cx="236" cy="197" r="3" fill="#BA7517"/>
  <text font-size="12" font-family="sans-serif" x="226" y="172" text-anchor="middle" fill="#412402" font-weight="500">:8000</text>
  <text font-size="11" font-family="sans-serif" x="226" y="236" text-anchor="middle" fill="#633806">API lab</text>
</g>
<g id="pb8443" style="cursor:pointer" onclick="mostrar(8443)">
  <rect x="296" y="158" width="88" height="68" rx="6" fill="#F4C0D1" stroke="#993556" stroke-width="1.5"/>
  <rect x="324" y="176" width="30" height="38" rx="4" fill="#993556" opacity=".3"/>
  <circle cx="350" cy="197" r="3" fill="#993556"/>
  <text font-size="12" font-family="sans-serif" x="340" y="172" text-anchor="middle" fill="#4B1528" font-weight="500">:8443</text>
  <text font-size="11" font-family="sans-serif" x="340" y="236" text-anchor="middle" fill="#72243E">HTTPS lab</text>
</g>
<g id="pb9999" style="cursor:pointer" onclick="mostrar(9999)">
  <rect x="410" y="158" width="88" height="68" rx="6" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="1.5"/>
  <rect x="438" y="176" width="30" height="38" rx="4" fill="#5F5E5A" opacity=".2"/>
  <circle cx="464" cy="197" r="3" fill="#888780"/>
  <text font-size="12" font-family="sans-serif" x="454" y="172" text-anchor="middle" fill="#444441" font-weight="500">:9999</text>
  <text font-size="11" font-family="sans-serif" x="454" y="236" text-anchor="middle" fill="#888780">cerrado</text>
</g>
<rect x="20" y="140" width="108" height="58" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="74" y="162" text-anchor="middle" fill="#2C2C2A">tu navegador</text>
<text font-size="11" font-family="sans-serif" x="74" y="176" text-anchor="middle" fill="#2C2C2A">o programa</text>
<text font-size="10" font-family="sans-serif" x="74" y="190" text-anchor="middle" fill="#888780">(cliente)</text>
<line x1="130" y1="168" x2="158" y2="168" stroke="#185FA5" stroke-width="1.5" marker-end="url(#arl)"/>
<rect x="20" y="254" width="640" height="50" rx="8" fill="#EAF3DE" stroke="#3B6D11" stroke-width="1" id="det-bg"/>
<text font-size="13" font-family="sans-serif" x="340" y="274" text-anchor="middle" fill="#173404" font-weight="500" id="det-title">👆 Pulsa una puerta para ver qué hay detrás</text>
<text font-size="11" font-family="sans-serif" x="340" y="292" text-anchor="middle" fill="#27500A" id="det-body"></text>
</svg>
</div>
<script>
var datos={22:{t:"Puerto 22 · SSH",b:"Terminal remota cifrada. En el Lab 2 nmap lo encontró cerrado (closed) en el servidor nginx.",c:"#085041"},80:{t:"Puerto 80 · HTTP",b:"Web sin cifrar. Nginx lo escucha y devuelve 301 redirigiendo a HTTPS:8443.",c:"#0C447C"},443:{t:"Puerto 443 · HTTPS",b:"Web cifrada con TLS. En producción Nginx escucha aquí; en el lab usamos el 8443.",c:"#3C3489"},8000:{t:"Puerto 8000 · API del lab",b:"FastAPI escucha aquí DENTRO de la red Docker. Sin ports: → invisible desde tu PC. Connection refused.",c:"#633806"},8443:{t:"Puerto 8443 · HTTPS del lab",b:"Mismo protocolo que el 443 pero sin necesitar root. Nginx lo publica con ports:8443:443.",c:"#72243E"},9999:{t:"Puerto 9999 · cerrado (closed)",b:"Nadie escucha. curl localhost:9999 → Connection refused. nmap lo marca como closed.",c:"#5F5E5A"}};
function mostrar(n){var d=datos[n];if(!d)return;var t=document.getElementById("det-title"),b=document.getElementById("det-body");t.textContent=d.t;t.setAttribute("fill",d.c);b.textContent=d.b;}
</script>

### 1.2 Protocolos seguros: HTTP/HTTPS, TLS y SSH

| Protocolo | Para qué | ¿Cifrado? |
|---|---|---|
| **HTTP** | Navegación web | ❌ No: todo viaja en claro |
| **HTTPS** | Navegación web segura | ✅ Sí, con **TLS** |
| **SSH** | Administración remota de un servidor (terminal) | ✅ Sí |

**HTTPS** no es un protocolo nuevo: es **HTTP sobre TLS**. **TLS** (*Transport Layer Security*) es la capa que cifra la comunicación y, mediante un **certificado**, garantiza que hablas con quien crees (recuerda los certificados de la UT1). Por eso el candado del navegador significa "cifrado + identidad verificada".

**SSH** (*Secure Shell*) permite abrir una terminal en un servidor remoto de forma cifrada. Sustituyó a Telnet, que enviaba las contraseñas en claro. Un comando típico:

```bash
ssh usuario@servidor        # abre una sesión remota cifrada
```

### 1.3 VPN: una red privada sobre una pública

Una **VPN** (*Virtual Private Network*) crea un **túnel cifrado** entre tu equipo y la red de la empresa a través de Internet. Es como tener un cable privado hasta la oficina, aunque estés en casa: todo lo que viaja por el túnel va cifrado y, para la red de la empresa, es como si estuvieras dentro.

<figure>

<svg width="100%" viewBox="0 0 680 260" role="img" xmlns="http://www.w3.org/2000/svg">
<title>Diagrama de VPN con túnel cifrado</title>
<desc>Un portátil en casa se conecta mediante un túnel VPN cifrado a través de Internet hasta la pasarela VPN de la empresa, accediendo a la red interna</desc>
<defs><marker id="arv" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>
<rect x="20" y="80" width="110" height="90" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="1.5"/>
<text font-size="12" font-family="sans-serif" x="75" y="118" text-anchor="middle" fill="#2C2C2A" font-weight="500">💻 Portátil</text>
<text font-size="11" font-family="sans-serif" x="75" y="134" text-anchor="middle" fill="#888780">en casa</text>
<text font-size="11" font-family="sans-serif" x="75" y="150" text-anchor="middle" fill="#185FA5">IP pública</text>
<rect x="22" y="185" width="106" height="20" rx="4" fill="#185FA5"/>
<text font-size="11" font-family="sans-serif" x="75" y="199" text-anchor="middle" fill="#E6F1FB">VPN: 10.8.0.2</text>
<rect x="145" y="68" width="390" height="110" rx="28" fill="none" stroke="#185FA5" stroke-width="1.5" stroke-dasharray="8 4"/>
<text font-size="12" font-family="sans-serif" x="340" y="90" text-anchor="middle" fill="#185FA5" font-weight="500">🔒 Túnel VPN cifrado</text>
<text font-size="11" font-family="sans-serif" x="340" y="106" text-anchor="middle" fill="#185FA5">WireGuard / OpenVPN / IPsec</text>
<ellipse cx="340" cy="148" rx="52" ry="26" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<ellipse cx="318" cy="137" rx="25" ry="17" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<ellipse cx="362" cy="135" rx="27" ry="18" fill="#FCEBEB" stroke="#E24B4A" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="340" y="152" text-anchor="middle" fill="#A32D2D">Internet</text>
<line x1="132" y1="128" x2="285" y2="128" stroke="#185FA5" stroke-width="2" marker-end="url(#arv)"/>
<line x1="395" y1="148" x2="525" y2="148" stroke="#185FA5" stroke-width="2" marker-end="url(#arv)"/>
<rect x="537" y="80" width="118" height="90" rx="8" fill="#FAC775" stroke="#BA7517" stroke-width="1.5"/>
<text font-size="12" font-family="sans-serif" x="596" y="114" text-anchor="middle" fill="#633806" font-weight="500">🔥 Pasarela VPN</text>
<text font-size="11" font-family="sans-serif" x="596" y="130" text-anchor="middle" fill="#633806">empresa</text>
<text font-size="11" font-family="sans-serif" x="596" y="148" text-anchor="middle" fill="#412402">10.8.0.1</text>
<rect x="537" y="192" width="118" height="44" rx="8" fill="#B5D4F4" stroke="#185FA5" stroke-width="1.5"/>
<text font-size="12" font-family="sans-serif" x="596" y="211" text-anchor="middle" fill="#042C53" font-weight="500">Red interna</text>
<text font-size="11" font-family="sans-serif" x="596" y="227" text-anchor="middle" fill="#042C53">10.0.0.0/24</text>
<line x1="596" y1="172" x2="596" y2="190" stroke="#185FA5" stroke-width="1.5" marker-end="url(#arv)"/>
<rect x="148" y="216" width="370" height="34" rx="8" fill="#EAF3DE" stroke="#3B6D11" stroke-width="1"/>
<text font-size="11" font-family="sans-serif" x="333" y="230" text-anchor="middle" fill="#173404" font-weight="500">✅ El portátil accede a la red interna como si estuviera físicamente en la oficina</text>
<text font-size="10" font-family="sans-serif" x="333" y="244" text-anchor="middle" fill="#27500A">puede hacer curl http://api:8000 directamente · misma subred virtual que el lab</text>
</svg>

<figcaption>Una VPN te mete dentro de la red privada de la empresa a través de internet. Por eso si levantaras una VPN hacia la red <code>interna</code> del lab, podrías llamar a la API directamente.</figcaption>
</figure>

Elementos de una VPN: el **túnel** (el canal cifrado), las **claves** (para cifrar y autenticar los extremos) y las **rutas** (qué tráfico va por el túnel y cuál no). Ejemplos reales: WireGuard, OpenVPN, IPsec.

### 1.4 Acceso remoto: pasarelas, autenticación, autorización y control de acceso

Cuando alguien accede desde fuera, el acceso pasa por una **pasarela** (*gateway*): un único punto de entrada que concentra los controles. En el laboratorio, esa pasarela será **Nginx**. Sobre ella se aplican las **tres A (AAA)**:

| | Pregunta | En el laboratorio |
|---|---|---|
| **Autenticación** | ¿Quién eres? | La cabecera `X-Token` de la API |
| **Autorización** | ¿Qué puedes hacer? | Sin token válido → `401` (denegado) |
| **Auditoría** (*accounting*) | ¿Qué hiciste y cuándo? | Los registros de Nginx y de la API |

### 1.5 Autenticación centralizada: RADIUS

En una empresa con muchos usuarios y servicios, no tiene sentido que cada servicio tenga su propia lista de contraseñas. **RADIUS** es un protocolo que **centraliza** la autenticación: los servicios preguntan a un servidor RADIUS "¿este usuario y contraseña son válidos?", y él responde. Así hay **una sola** fuente de identidades (altas, bajas y cambios en un único sitio). Se usa mucho en wifi corporativas y VPN. No lo montaremos, pero debes reconocer **qué problema resuelve**: evitar tener las credenciales repartidas por todos lados.

!!! note "Lo esencial de la teoría para el test"
    DMZ = zona intermedia; Internet nunca llega directo a la LAN. HTTPS = HTTP + TLS (cifrado + identidad). SSH = terminal remota cifrada (sustituye a Telnet). VPN = túnel cifrado (túnel + claves + rutas). Pasarela = punto único de entrada. AAA = autenticación/autorización/auditoría. RADIUS = autenticación centralizada.
## Parte 2 · Laboratorio: acceso seguro a una intranet

Vas a montar la intranet de una empresa pequeña: una **API privada** (FastAPI) con datos de empleados, protegida detrás de una **pasarela Nginx** con **HTTPS**. La API **nunca** se expone directamente a Internet: solo se llega a ella a través de la pasarela. Comprobarás el aislamiento, los códigos HTTP, el cifrado y el acceso SSH.

<figure>

<svg width="100%" viewBox="0 0 680 350" role="img" xmlns="http://www.w3.org/2000/svg">
<title>Arquitectura Docker del laboratorio UT3</title>
<desc>Red DMZ con Nginx expuesto en puertos 8080 y 8443, y red interna con la API FastAPI sin puertos publicados, solo accesible desde dentro</desc>
<defs><marker id="arl" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>
<rect x="20" y="130" width="100" height="80" rx="8" fill="#F1EFE8" stroke="#5F5E5A" stroke-width="1.5"/>
<text font-size="12" font-family="sans-serif" x="70" y="162" text-anchor="middle" fill="#2C2C2A" font-weight="500">💻 Tu PC</text>
<text font-size="11" font-family="sans-serif" x="70" y="178" text-anchor="middle" fill="#888780">(anfitrión)</text>
<text font-size="10" font-family="sans-serif" x="70" y="200" text-anchor="middle" fill="#888780">fuera de Docker</text>
<line x1="122" y1="158" x2="168" y2="158" stroke="#185FA5" stroke-width="1.5" marker-end="url(#arl)"/>
<text font-size="10" font-family="sans-serif" x="145" y="150" text-anchor="middle" fill="#185FA5">HTTPS :8443</text>
<line x1="122" y1="185" x2="168" y2="185" stroke="#888780" stroke-width="1" stroke-dasharray="4 3" marker-end="url(#arl)"/>
<text font-size="10" font-family="sans-serif" x="145" y="200" text-anchor="middle" fill="#888780">HTTP :8080 → 301</text>
<rect x="170" y="20" width="210" height="300" rx="12" fill="#E1F5EE" stroke="#0F6E56" stroke-width="1.5" stroke-dasharray="6 3"/>
<text font-size="12" font-family="sans-serif" x="275" y="42" text-anchor="middle" fill="#085041" font-weight="500">red dmz</text>
<text font-size="10" font-family="sans-serif" x="275" y="58" text-anchor="middle" fill="#085041">expuesta al anfitrión</text>
<rect x="190" y="100" width="170" height="130" rx="8" fill="#9FE1CB" stroke="#0F6E56" stroke-width="1.5"/>
<text font-size="12" font-family="sans-serif" x="275" y="124" text-anchor="middle" fill="#04342C" font-weight="500">⚙️ Nginx</text>
<text font-size="11" font-family="sans-serif" x="275" y="140" text-anchor="middle" fill="#04342C">pasarela HTTPS</text>
<rect x="195" y="152" width="76" height="20" rx="4" fill="#0F6E56"/>
<text font-size="10" font-family="sans-serif" x="233" y="166" text-anchor="middle" fill="#E1F5EE">8080:80</text>
<rect x="279" y="152" width="76" height="20" rx="4" fill="#0F6E56"/>
<text font-size="10" font-family="sans-serif" x="317" y="166" text-anchor="middle" fill="#E1F5EE">8443:443</text>
<text font-size="10" font-family="sans-serif" x="275" y="192" text-anchor="middle" fill="#085041">redes: dmz + interna</text>
<text font-size="10" font-family="sans-serif" x="275" y="208" text-anchor="middle" fill="#085041">puente entre los dos mundos</text>
<line x1="382" y1="168" x2="438" y2="168" stroke="#0F6E56" stroke-width="2" marker-end="url(#arl)"/>
<text font-size="10" font-family="sans-serif" x="410" y="158" text-anchor="middle" fill="#085041">proxy_pass</text>
<text font-size="10" font-family="sans-serif" x="410" y="182" text-anchor="middle" fill="#085041">http://api:8000</text>
<rect x="440" y="20" width="220" height="300" rx="12" fill="#E6F1FB" stroke="#185FA5" stroke-width="1.5" stroke-dasharray="6 3"/>
<text font-size="12" font-family="sans-serif" x="550" y="42" text-anchor="middle" fill="#0C447C" font-weight="500">red interna</text>
<text font-size="10" font-family="sans-serif" x="550" y="58" text-anchor="middle" fill="#0C447C">internal: true · sin salida</text>
<rect x="458" y="90" width="184" height="150" rx="8" fill="#B5D4F4" stroke="#185FA5" stroke-width="1.5"/>
<text font-size="12" font-family="sans-serif" x="550" y="116" text-anchor="middle" fill="#042C53" font-weight="500">🐍 FastAPI</text>
<text font-size="11" font-family="sans-serif" x="550" y="132" text-anchor="middle" fill="#042C53">API privada</text>
<rect x="463" y="144" width="174" height="20" rx="4" fill="#A32D2D"/>
<text font-size="10" font-family="sans-serif" x="550" y="158" text-anchor="middle" fill="#FCEBEB">❌ sin ports: → invisible</text>
<text font-size="10" font-family="sans-serif" x="550" y="182" text-anchor="middle" fill="#185FA5">GET /salud → 200</text>
<text font-size="10" font-family="sans-serif" x="550" y="198" text-anchor="middle" fill="#185FA5">GET /empleados → 401/200</text>
<text font-size="10" font-family="sans-serif" x="550" y="214" text-anchor="middle" fill="#042C53">puerto 8000 (interno)</text>
<line x1="122" y1="290" x2="456" y2="290" stroke="#E24B4A" stroke-width="1.5" stroke-dasharray="5 3" marker-end="url(#arl)"/>
<text font-size="10" font-family="sans-serif" x="288" y="280" text-anchor="middle" fill="#A32D2D">curl localhost:8000 → Connection refused ❌</text>
</svg>

<figcaption>Arquitectura del laboratorio: tu PC solo puede hablar con Nginx (que tiene <code>ports:</code>). La API vive en la red <code>interna</code> sin puertos publicados: Nginx es el único que llega a ella, y tú solo llegas a la API a través de Nginx.</figcaption>
</figure>

!!! tip "Ficheros listos para usar"
    Todo el laboratorio está en la carpeta **`lab/`** del repositorio del curso, con esta estructura. No tienes que copiar nada a mano:

    ```text
    lab/
    ├── compose.yaml              # define servicios y redes
    ├── generar_certificado.sh    # crea el certificado de laboratorio
    ├── api/                      # la API privada (FastAPI)
    │   ├── app.py
    │   ├── Dockerfile
    │   └── requirements.txt
    └── nginx/                    # la pasarela
        ├── nginx.conf
        └── Dockerfile
    ```

### Paso 1 · Los servicios y las redes (Docker Compose)

El `compose.yaml` define **dos servicios** y, sobre todo, **dos redes**, que es donde está la seguridad:

```yaml title="lab/compose.yaml"
services:
  # Pasarela: única cara visible. Está en la DMZ (publicada) y en la red interna.
  nginx:
    build: ./nginx
    ports:
      - "8080:80"      # HTTP del host -> redirige a HTTPS
      - "8443:443"     # HTTPS del host -> pasarela
    volumes:
      - ./nginx/certs:/etc/nginx/certs:ro
    networks:
      - dmz
      - interna
    depends_on:
      - api
    security_opt:
      - no-new-privileges:true

  # API: SOLO en la red interna. No tiene 'ports', así que el host no la ve.
  api:
    build: ./api
    networks:
      - interna
    security_opt:
      - no-new-privileges:true

networks:
  dmz:
  interna:
    internal: true     # esta red no tiene salida a internet: aislamiento
```

**Lo importante:** la API **no tiene `ports`**. Eso significa que desde tu ordenador (el host) **no existe** una forma de llamarla directamente: solo es alcanzable desde dentro de la red `interna`, donde también está Nginx. La pasarela es el único puente.

### Paso 2 · La API con FastAPI

**FastAPI** es un framework de Python para crear APIs web rápidamente. La nuestra tiene tres *endpoints* y exige un **token** para los datos sensibles:

```python title="lab/api/app.py"
from fastapi import FastAPI, HTTPException, Header

app = FastAPI(title="Intranet API")

EMPLEADOS = {
    1: {"nombre": "Ana García", "departamento": "Sistemas"},
    2: {"nombre": "Luis Pérez", "departamento": "Ventas"},
}
TOKEN_VALIDO = "secreto-de-laboratorio"

@app.get("/salud")
def salud():
    """Comprobación de vida del servicio (no requiere token)."""
    return {"estado": "ok"}

@app.get("/empleados")
def listar(x_token: str = Header(default="")):
    """Lista los empleados. Requiere cabecera X-Token válida."""
    if x_token != TOKEN_VALIDO:
        raise HTTPException(status_code=401, detail="token no válido")
    return list(EMPLEADOS.values())

@app.get("/empleados/{id}")
def obtener(id: int, x_token: str = Header(default="")):
    """Devuelve un empleado por su id. Requiere token válido."""
    if x_token != TOKEN_VALIDO:
        raise HTTPException(status_code=401, detail="token no válido")
    if id not in EMPLEADOS:
        raise HTTPException(status_code=404, detail="no existe")
    return EMPLEADOS[id]
```

- `/salud` es público: sirve para comprobar que el servicio vive.
- `/empleados` y `/empleados/{id}` exigen la cabecera `X-Token`. Sin ella, devuelven **401** (no autorizado): esto es la **autenticación** de las AAA.

### Paso 3 · Generar el certificado de laboratorio

HTTPS necesita un certificado. Como es un laboratorio, creamos uno **autofirmado** (válido para pruebas, no para producción). El script usa `openssl`:

```bash title="lab/generar_certificado.sh"
#!/bin/sh
mkdir -p nginx/certs
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout nginx/certs/key.pem \
    -out nginx/certs/cert.pem \
    -days 365 \
    -subj "/CN=intranet.local"
echo "Certificado creado en nginx/certs/"
```

Ejecútalo una vez antes de levantar los contenedores:

```bash title="Terminal (dentro de lab/)"
sh generar_certificado.sh
```

### Paso 4 · Nginx como pasarela (sin exponer la API)

Nginx recibe las peticiones de fuera y las **reenvía** a la API por la red interna. Además, obliga a usar HTTPS: si alguien entra por HTTP (puerto 80), lo redirige a HTTPS (443).

```nginx title="lab/nginx/nginx.conf"
events {}

http {
    # Redirige todo el tráfico HTTP (80) a HTTPS (443)
    server {
        listen 80;
        return 301 https://$host$request_uri;
    }

    # Punto de entrada seguro
    server {
        listen 443 ssl;
        server_name intranet.local;

        ssl_certificate     /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;

        # Reenvía las peticiones a la API, que vive en la red interna
        location / {
            proxy_pass http://api:8000;
            proxy_set_header Host $host;
        }
    }
}
```

Fíjate en `proxy_pass http://api:8000`: Nginx llama a la API por su **nombre de servicio** (`api`), que solo se resuelve **dentro** de la red Docker. El `301` de la primera sección es una **redirección permanente** a HTTPS.

**Levanta todo el laboratorio:**

```bash title="Terminal (dentro de lab/)"
docker compose up --build -d
```

### Paso 5 · Probar los endpoints con `curl` y ver los códigos HTTP

Ahora comprueba el comportamiento desde fuera. La opción `-k` le dice a `curl` que acepte el certificado autofirmado (solo en laboratorio); `-i` muestra la cabecera con el código HTTP.

```bash title="Terminal"
# 1) Salud del servicio (público) -> 200 OK
curl -k https://localhost:8443/salud

# 2) Listar empleados SIN token -> 401 (no autorizado)
curl -k -i https://localhost:8443/empleados

# 3) Listar empleados CON token -> 200 OK
curl -k -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados

# 4) Un empleado que no existe -> 404
curl -k -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados/99

# 5) Entrar por HTTP -> 301 (redirige a HTTPS)
curl -i http://localhost:8080/salud
```

| Petición | Código esperado | Qué demuestra |
|---|---|---|
| `/salud` | `200` | El servicio funciona |
| `/empleados` sin token | `401` | La autenticación protege los datos |
| `/empleados` con token | `200` | Con credencial válida, hay acceso |
| `/empleados/99` | `404` | El recurso no existe |
| `http://...` (puerto 80) | `301` | Se fuerza el uso de HTTPS |

### Paso 6 · Comprobar el aislamiento entre redes

Aquí se ve por qué la arquitectura es segura. Intenta llamar a la API **directamente**, saltándote la pasarela:

```bash title="Terminal"
# La API escucha en el 8000, pero DENTRO de la red interna.
# Desde el host no hay ningún puerto publicado hacia ella:
curl http://localhost:8000/salud
```

```text title="Resultado"
curl: (7) Failed to connect to localhost port 8000: Connection refused
```

**No se puede.** La API no tiene ningún puerto publicado hacia el host: solo Nginx puede hablar con ella, porque comparten la red `interna`. Puedes confirmar que Nginx **sí** la alcanza desde dentro:

```bash title="Terminal"
docker compose exec nginx wget -qO- http://api:8000/salud
```

```text title="Resultado"
{"estado":"ok"}
```

Esto es la **segmentación de redes** en acción: la API está en una zona aislada (`internal: true`, sin salida a Internet) y solo la pasarela, que hace de puente controlado, puede llegar a ella.

### Paso 7 · Acceso remoto con SSH

El laboratorio ya tiene SSH instalado en el contenedor nginx. Conéctate:

```bash title="Terminal"
ssh root@localhost -p 2222
# contraseña: laboratorio
```

Una vez dentro puedes inspeccionar el servidor:

```bash title="Dentro del contenedor nginx"
cat /etc/nginx/nginx.conf
ls /etc/nginx/certs/
nginx -t
exit
```

**VPN** — si levantaras un servidor WireGuard en la DMZ, tu equipo entraría en la red `interna` y podrías llamar a `http://api:8000` directamente, como hace nginx. Eso es lo que hace una VPN: te convierte en un miembro más de la red privada.

### Paso 8 · Probar los endpoints con curl

```bash title="Terminal"
# salud: público, sin token
curl -k https://localhost:8443/salud

# listar empleados sin token → 401
curl -k -i https://localhost:8443/empleados

# listar empleados con token → 200
curl -k -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados

# empleado concreto → 200
curl -k -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados/1

# empleado inexistente → 404
curl -k -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados/99

# solo el código de respuesta
curl -k -s -o /dev/null -w "%{http_code}\n" https://localhost:8443/salud
```

**Apaga el laboratorio:**

```bash
docker compose down
```

!!! success "🏅 Laboratorio completado"
    Intranet con DMZ, pasarela HTTPS, API privada, SSH y aislamiento de redes. Seguridad perimetral aplicada.

### 🔍 Comprueba tú mismo

Estas preguntas y experimentos nacen directamente del laboratorio. Algunas te piden que **pruebes algo** con el laboratorio levantado; otras que **pienses** sobre lo que viste.

### Sobre el compose y el aislamiento

**A1.** Con el laboratorio levantado, ejecuta desde tu terminal:
```bash
curl http://localhost:8000/salud
```
¿Qué ocurre? Ahora prueba:
```bash
curl -k https://localhost:8443/salud
```
¿Qué diferencia hay? Explica por qué la primera no funciona y la segunda sí.

**A2.** Mira el `compose.yaml`. La API no tiene `ports:` pero Nginx sí. ¿Qué pasaría si añadieras `ports: ["8000:8000"]` a la API? ¿Sería eso un problema de seguridad? ¿Por qué?

**A3.** La red `interna` tiene `internal: true`. ¿Qué significa eso? ¿Qué pasaría si la API intentara hacer una petición a internet desde dentro del contenedor?

### Sobre los endpoints y los códigos HTTP

**A4.** Con el laboratorio levantado, ejecuta estos tres comandos y anota el código HTTP que devuelve cada uno:
```bash
curl -k -o /dev/null -s -w "%{http_code}\n" https://localhost:8443/empleados
curl -k -o /dev/null -s -w "%{http_code}\n" -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados
curl -k -o /dev/null -s -w "%{http_code}\n" -H "X-Token: secreto-de-laboratorio" https://localhost:8443/empleados/99
```
¿Qué significa cada código? ¿Cuál corresponde a autenticación fallida, cuál a éxito y cuál a recurso inexistente?

**A5.** En `app.py`, el endpoint `/salud` no comprueba el token pero `/empleados` sí. ¿Por qué tiene sentido que el endpoint de salud sea público y el de datos sea privado?

### Sobre HTTPS y el certificado

**A6.** Ejecuta `curl https://localhost:8443/salud` **sin** la opción `-k`. ¿Qué error da? ¿Por qué el certificado de laboratorio provoca ese error y uno de una CA reconocida no lo haría?

**A7.** El `nginx.conf` tiene esta línea en el servidor que escucha en el puerto 80:
```nginx
return 301 https://$host$request_uri;
```
Prueba `curl -i http://localhost:8080/salud`. ¿Qué código HTTP ves en la primera línea de la respuesta? ¿Qué hace Nginx con tu petición?
## Cómo se evalúa esta unidad (RA3)

La UT3 se evalúa con un **examen tipo test**.

!!! tip "La nota, sin sorpresas"
    **Nota = (aciertos ÷ nº de preguntas) × 10.** Los fallos no restan. Se aprueba con 5.

## Simulacro de examen tipo test

> 20 preguntas. Mezclan teoría y lo que viste y probaste en el laboratorio. Una sola respuesta correcta.

**1.** El `compose.yaml` del laboratorio define la API así:

```yaml
  api:
    build: ./api
    networks:
      - interna
```

Ejecutaste `curl http://localhost:8000/salud` y obtuviste *Connection refused*. ¿Por qué?

- A) La API tiene un error
- B) La API no publica ningún puerto hacia el anfitrión; solo Nginx puede llegar a ella desde la red interna
- C) Falta el certificado
- D) El token es incorrecto

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La API no tiene <code>ports:</code> en el compose, así que no existe ningún puente entre la red Docker y tu máquina. Es el aislamiento funcionando correctamente.</details>

**2.** Accediste al endpoint `/empleados` sin incluir ningún token en la petición. El servidor respondió con el código **401**. ¿Qué significa?

- A) El recurso no existe
- B) La petición no está autenticada: falta o es incorrecto el token
- C) El servidor no responde
- D) La conexión fue rechazada

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> HTTP 401 significa "no autorizado": la API exige la cabecera <code>X-Token</code> y no se envió.</details>

**3.** Al incluir la cabecera `X-Token: secreto-de-laboratorio` en la misma petición a `/empleados`, el servidor respondió con **200**. ¿Qué significa ese cambio de 401 a 200?

- A) Error del servidor
- B) Petición correcta, recurso devuelto
- C) Redirección a otra URL
- D) Recurso no encontrado

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> HTTP 200 OK es la respuesta estándar de éxito: la petición fue correcta y el servidor devuelve lo que se pidió.</details>

**4.** Con token válido pediste `/empleados/99`, un empleado que no existe en la base de datos. El servidor respondió **404**. ¿Qué indica ese código y qué lo distingue del 401?

- A) El token es incorrecto
- B) El empleado con id 99 no existe en la base de datos
- C) El servidor no está disponible
- D) El certificado ha caducado

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> HTTP 404 "Not Found": la autenticación fue correcta pero el recurso solicitado no existe.</details>

**5.** El `nginx.conf` tiene este bloque:

```nginx
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

Al ejecutar `curl -i http://localhost:8080/salud` viste el código **301** en la respuesta. ¿Para qué sirve esa directiva?

- A) Bloquear todo el tráfico HTTP
- B) Redirigir permanentemente el tráfico HTTP a HTTPS, forzando cifrado
- C) Devolver un error al cliente
- D) Reiniciar el servidor

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> El código 301 es una redirección permanente. Nginx recibe la petición HTTP y le dice al cliente que vuelva usando HTTPS.</details>

**6.** Al ejecutar `curl https://localhost:8443/salud` sin la opción `-k` obtuviste:

```text
curl: (60) SSL certificate problem: self-signed certificate
More details here: https://curl.se/docs/sslcerts.html
```

¿Por qué da ese error con el certificado del laboratorio?

- A) El servidor no tiene certificado
- B) El certificado es autofirmado: ninguna CA reconocida lo avala, así que el cliente desconfía
- C) El puerto 8443 está cerrado
- D) El token es incorrecto

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Un certificado autofirmado cifra igual que uno de una CA, pero como nadie externo lo ha verificado, el cliente lo rechaza por defecto. La opción <code>-k</code> le dice que lo acepte igualmente (solo para laboratorio).</details>

**7.** ¿Qué diferencia hay entre un certificado autofirmado (como el del lab) y uno emitido por una CA?

- A) El autofirmado cifra más
- B) El de una CA está avalado por una entidad de confianza; el autofirmado no
- C) No hay diferencia técnica
- D) El autofirmado caduca antes

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La diferencia es de confianza, no de cifrado. Una CA verifica la identidad del servidor antes de emitir el certificado; el autofirmado lo firma uno mismo.</details>

**8.** El `compose.yaml` define las redes así:

```yaml
networks:
  dmz:
  interna:
    internal: true
```

¿Qué implica `internal: true` para los contenedores que están solo en esa red (como la API)?

- A) Que va más rápida
- B) Que no tiene salida a internet; está aislada
- C) Que solo acepta HTTPS
- D) Que es visible desde fuera del contenedor

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> <code>internal: true</code> crea una red sin enrutamiento hacia el exterior. La API vive ahí y no puede ni ser alcanzada ni llegar a internet por su cuenta.</details>

**9.** En el `compose.yaml`:

```yaml
  nginx:
    networks:
      - dmz
      - interna
  api:
    networks:
      - interna
```

¿Por qué Nginx está en dos redes y la API solo en una?

- A) Es un error de configuración
- B) Nginx necesita estar en las dos para hacer de puente entre el exterior y la API
- C) Para que la API vaya más rápida
- D) Para ahorrar memoria

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Nginx es la pasarela: recibe tráfico del exterior (red dmz) y lo reenvía a la API (red interna). La API no necesita estar en la dmz porque nadie debe llegar a ella directamente.</details>

**10.** En la configuración de Nginx, la pasarela reenvía las peticiones usando el nombre `api` para localizar el contenedor de la API. ¿Por qué funciona ese nombre dentro de la red Docker aunque no sea una IP real?

- A) `api` es una IP pública fija
- B) Docker resuelve el nombre `api` dentro de la red interna como la dirección del contenedor
- C) El puerto 8000 está publicado hacia el anfitrión
- D) Nginx adivina la dirección del contenedor

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> En una red Docker, los contenedores se pueden localizar por su nombre de servicio. Nginx usa ese nombre internamente; desde fuera de Docker, ese nombre no existe.</details>

**11.** ¿Qué es una **DMZ** en seguridad perimetral?

- A) La red más interna, donde está la base de datos
- B) Una zona intermedia entre internet y la red interna, donde van los servicios públicos
- C) Un tipo de firewall
- D) Una VPN

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La DMZ es la "recepción": aloja lo que debe ser accesible desde fuera sin dar acceso directo a lo valioso de dentro. En el lab, Nginx vive ahí.</details>

**12.** El endpoint `/empleados` de la API comprueba una cabecera `X-Token` antes de devolver los datos. Si falta o es incorrecta, devuelve 401. ¿Qué parte de las **AAA** (autenticación, autorización, auditoría) implementa este mecanismo?

- A) El certificado SSL
- B) La cabecera `X-Token` que la API comprueba en cada petición
- C) El puerto 8443
- D) El fichero `nginx.conf`

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La autenticación responde a "¿quién eres?". En el lab, la API verifica el token antes de devolver datos: si no está o es incorrecto, devuelve 401.</details>

**13.** Al probar la API con curl usas siempre `https://localhost:8443` y nunca `http://localhost:8000`. ¿Por qué?

```bash
curl -k https://localhost:8443/salud           # correcto
curl http://localhost:8000/salud              # Connection refused
```

- A) Por casualidad; cualquiera de las dos funcionaría
- B) Prueba el sistema como lo haría un cliente real: pasando por la pasarela, no directamente a la API
- C) Porque el puerto 8000 da error siempre
- D) Para evitar el certificado

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Una prueba realista simula cómo accede un usuario de verdad: a través de la pasarela HTTPS. Saltar a la API directa no sería un test válido porque en producción eso no es posible.</details>

**14.** ¿Qué diferencia hay entre **HTTP** y **HTTPS**?

- A) HTTPS es más lento pero funciona igual
- B) HTTPS cifra la comunicación con TLS y verifica la identidad del servidor
- C) HTTP usa el puerto 443 y HTTPS el 80
- D) No hay diferencia en seguridad

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> HTTPS = HTTP + TLS. TLS aporta cifrado (nadie puede leer el tráfico) e identidad (el certificado verifica quién es el servidor).</details>

**15.** ¿Para qué sirve **SSH**?

- A) Para navegar por webs cifradas
- B) Para abrir una terminal remota cifrada en un servidor
- C) Para generar certificados
- D) Para filtrar tráfico de red

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> SSH permite administrar un servidor de forma remota y cifrada. Sustituyó a Telnet, que enviaba todo en claro incluyendo contraseñas.</details>

**16.** En el lab, ejecutaste `curl http://localhost:8000/salud` y obtuviste *Connection refused*, porque la API no publica puertos. Solo Nginx llega a ella por la red `interna`:

```yaml
networks:
  interna:
    internal: true
```

Si levantaras una **VPN** que te conectase a esa red `interna`, ¿qué cambiaría?

- A) Nada, el laboratorio no la soporta
- B) Entrar en la red interna como si estuvieras físicamente en ella, pudiendo llegar a la API directamente
- C) Solo cifrar el tráfico web
- D) Deshabilitar el certificado autofirmado

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La VPN te convierte en un miembro más de la red interna. Desde ahí podrías llamar a <code>http://api:8000</code> directamente, igual que hace Nginx.</details>

**17.** ¿Qué problema resuelve **RADIUS**?

- A) Cifrar el disco del servidor
- B) Centralizar la autenticación en un único punto en vez de tener credenciales repartidas por cada servicio
- C) Generar certificados automáticamente
- D) Bloquear ataques de fuerza bruta

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> RADIUS permite que todos los servicios pregunten a un único servidor de autenticación. Alta, baja o cambio de contraseña se hace en un solo sitio.</details>

**18.** ¿Qué significa en el lab que Nginx haga de **pasarela**?

- A) Que guarda copias de seguridad
- B) Que es el único punto de entrada: toda petición pasa por él antes de llegar a la API
- C) Que cifra los datos almacenados
- D) Que gestiona los usuarios

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> La pasarela concentra el control: autenticación, cifrado TLS, registro de accesos. La API no sabe nada de todo eso; se lo delega a Nginx.</details>

**19.** Para el laboratorio generaste el certificado con `openssl` usando la opción `-x509`. El resultado es un certificado que tiene el mismo emisor que el sujeto. ¿Qué tipo de certificado es y por qué los navegadores no lo aceptan por defecto?

- A) Un certificado emitido por una CA reconocida
- B) Un certificado autofirmado, válido para laboratorio pero no para producción
- C) Un certificado caducado
- D) Un certificado sin clave privada

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> <code>-x509</code> genera un certificado autofirmado: el propio sujeto lo firma, sin que ninguna CA lo valide. Perfecto para pruebas, inaceptable para producción.</details>

**20.** La API tiene un endpoint `/salud` que responde sin pedir ningún token, y un endpoint `/empleados` que sí lo exige. ¿Por qué es buena práctica que el endpoint de salud sea público?

- A) Para evitar usar el certificado
- B) Para que sistemas de monitorización puedan verificar que el servicio está vivo sin necesitar credenciales
- C) Porque es obligatorio en FastAPI
- D) Para que los atacantes no detecten el servidor

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Los sistemas de monitorización (balanceadores, orquestadores como Kubernetes) comprueban la salud del servicio periódicamente. Necesitan hacerlo sin autenticarse.</details>

**21.** En el laboratorio, Nginx escucha en el puerto **8443** en vez del 443 estándar. ¿Por qué?

- A) El 443 es menos seguro
- B) Los puertos por debajo del 1024 requieren permisos de root; el 8443 no
- C) El 8443 es más rápido
- D) El certificado solo funciona en el 8443

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> En Linux, los puertos privilegiados (0-1023) solo los puede abrir el usuario root. En el laboratorio corremos como usuario sin privilegios, así que usamos el 8443 (equivalente al 443) y el 8080 (equivalente al 80) para no necesitar sudo.</details>

**22.** nmap encontró el puerto 80 como `open` y el 22 como `closed` en el servidor del Lab 2. ¿Qué diferencia hay entre `open` y `closed`?

- A) `open` es más rápido que `closed`
- B) `open` significa que hay un servicio escuchando; `closed` significa que el sistema responde pero nadie escucha en ese puerto
- C) `closed` significa que hay un firewall bloqueando
- D) Son sinónimos, nmap los usa indistintamente

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> Un puerto <code>open</code> tiene un servicio activo (nginx en el 80). Un puerto <code>closed</code> el sistema operativo lo conoce pero no hay nadie detrás: si conectas, obtienes <i>Connection refused</i>. Un tercer estado, <code>filtered</code>, indica que un firewall descarta los paquetes sin responder.</details>

**23.** ¿Por qué la API del laboratorio (que escucha en el puerto 8000) no es accesible desde tu PC aunque el contenedor esté en marcha?

- A) Porque el puerto 8000 está reservado
- B) Porque sin `ports:` en el compose, el puerto 8000 no está publicado hacia el anfitrión: solo existe dentro de la red Docker
- C) Porque la API tiene un error de configuración
- D) Porque el puerto 8000 requiere HTTPS

<details class="sol"><summary>Ver respuesta</summary><b>Correcta: B.</b> En Docker Compose, <code>ports:</code> es el puente entre el puerto del contenedor y tu máquina. Sin ese puente, el servicio escucha internamente pero es invisible desde fuera. Es la implementación práctica del aislamiento de redes: la API vive en la red <code>interna</code> y no tiene salida.</details>
