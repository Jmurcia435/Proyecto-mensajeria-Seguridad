# cipher

Aplicación full-stack de mensajería privada. El navegador genera una identidad ECDH P-256 y una firma Ed25519 para cada usuario. Los mensajes usan ECDH + HKDF + AES-256-GCM. El servidor solo almacena sobres cifrados y claves públicas firmadas; nunca almacena claves privadas ni texto plano.

## Requisitos

- Node.js 20 o superior.
- npm.

## Desarrollo

```bash
npm install
npm run dev
```

La interfaz queda en `http://localhost:5173` y la API en `http://localhost:8787`. SQLite se crea automáticamente en `data/cipher.sqlite`.

## Producción local

```bash
npm run build
NODE_ENV=production npm start
```

En Windows o para evitar configurar variables manualmente, puedes usar directamente:

```bash
npm run build
npm run start:local
```

La aplicación estará disponible en `http://localhost:8787`.

En Windows PowerShell:

```powershell
npm run build
$env:NODE_ENV = "production"
npm start
```

El servidor sirve la aplicación compilada y la API desde el mismo puerto (`8787` por defecto). En producción local sobre `http://localhost`, la cookie funciona sin configuración adicional. Para publicar el servicio detrás de HTTPS, activa la cookie segura antes de iniciar:

```powershell
$env:NODE_ENV = "production"
$env:COOKIE_SECURE = "true"
npm start
```

No uses `COOKIE_SECURE=true` si vas a entrar por HTTP local, porque el navegador rechazará la cookie de sesión.

## Flujo de seguridad

- Las contraseñas se almacenan en el servidor con `scrypt` y salt aleatorio.
- Las sesiones usan tokens aleatorios en cookies `HttpOnly`, `SameSite=Lax` y con expiración.
- Las claves privadas ECDH y Ed25519 se generan como no extraíbles con Web Crypto y se guardan como `CryptoKey` en IndexedDB; nunca salen del navegador.
- La clave AES de cada mensaje se deriva del secreto ECDH mediante HKDF-SHA-256. Cada copia usa un salt e IV aleatorios nuevos.
- Cada mensaje se cifra dos veces con claves efímeras ECDH distintas: una copia para el destinatario y otra para el remitente. Así ambos pueden leerlo normalmente con su propia clave privada, aunque el servidor solo almacena los dos sobres cifrados.
- La clave pública ECDH se firma con Ed25519. El cliente verifica la firma y muestra una huella que se puede comparar; además fija la clave observada para detectar cambios.
- La aplicación usa una Content Security Policy estricta y construye el DOM con APIs seguras, sin `innerHTML`.
- Las peticiones que cambian estado requieren un token CSRF. El login tiene límite de cinco intentos por usuario/IP cada quince minutos.
- El servidor valida usernames, destinatarios y el tamaño del sobre cifrado.

Esta versión proporciona mensajería persistente entre usuarios registrados en la misma instancia. Para un entorno público de alta disponibilidad conviene añadir HTTPS gestionado, copias de seguridad cifradas de SQLite, rate limiting, rotación de sesiones y monitorización.
