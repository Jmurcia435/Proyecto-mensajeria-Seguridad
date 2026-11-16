import './style.css'

type Identity = { id: number; username: string; publicKey: string; signingPublicKey: string; publicKeySignature: string; fingerprint: string }
type Contact = Identity
type Envelope = { ciphertext: string; iv: string; salt: string; ephemeralPublicKey: string }
type Message = { id: string; senderId: number; recipientId: number; senderCiphertext: string | null; senderIv: string | null; senderSalt: string | null; senderEphemeralPublicKey: string | null; recipientCiphertext: string | null; recipientIv: string | null; recipientSalt: string | null; recipientEphemeralPublicKey: string | null; sentAt: string }
type Chat = { contact: Contact; messages: Message[] }
type ApiError = { error?: string }
type StoredKeys = { id: number; privateKey: CryptoKey; signingPrivateKey: CryptoKey }

const app = document.querySelector<HTMLDivElement>('#app')!
let identity: Identity | null = null
let privateKey: CryptoKey | null = null

const api = async <T>(url: string, options: RequestInit = {}): Promise<T> => {
  const method = options.method ?? 'GET'
  const headers = new Headers(options.headers)
  headers.set('Content-Type', 'application/json')
  if (method !== 'GET' && method !== 'HEAD') {
    const csrf = document.cookie.split('; ').find((part) => part.startsWith('cipher_csrf='))?.split('=')[1]
    if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf))
  }
  const response = await fetch(`/api${url}`, { ...options, credentials: 'include', headers })
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as ApiError
    throw new Error(body.error ?? 'No se pudo completar la operación.')
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>
}
const json = (body: unknown): RequestInit => ({ method: 'POST', body: JSON.stringify(body) })
const b64 = (value: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(value)))
const bytes = (value: string) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0))
const buffer = (value: Uint8Array) => Uint8Array.from(value).buffer as ArrayBuffer
const textEncoder = new TextEncoder()
const formatTime = (date: string) => new Intl.DateTimeFormat('es', { hour: '2-digit', minute: '2-digit' }).format(new Date(date))

type Props = Record<string, string | boolean | number | EventListener | undefined>
function node<K extends keyof HTMLElementTagNameMap>(tag: K, props: Props = {}, children: Array<Node | string> = []) {
  const element = document.createElement(tag)
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined) continue
    if (key.startsWith('on') && typeof value === 'function') element.addEventListener(key.slice(2).toLowerCase(), value)
    else if (key === 'className') element.className = String(value)
    else if (value === true) element.setAttribute(key, '')
    else element.setAttribute(key, String(value))
  }
  element.append(...children.map((child) => typeof child === 'string' ? document.createTextNode(child) : child))
  return element
}
const svg = (name: string, size = 20) => {
  const element = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
  element.setAttribute('class', 'icon'); element.setAttribute('width', String(size)); element.setAttribute('height', String(size)); element.setAttribute('viewBox', '0 0 24 24'); element.setAttribute('fill', 'none'); element.setAttribute('stroke', 'currentColor'); element.setAttribute('stroke-width', '1.8'); element.setAttribute('stroke-linecap', 'round'); element.setAttribute('stroke-linejoin', 'round')
  const paths: Record<string, Array<[string, Record<string, string>]>> = {
    lock: [['rect', { x: '4', y: '10', width: '16', height: '11', rx: '2' }], ['path', { d: 'M8 10V7a4 4 0 0 1 8 0v3' }], ['path', { d: 'M12 14v3' }]],
    arrow: [['path', { d: 'M5 12h14' }], ['path', { d: 'm13 6 6 6-6 6' }]],
    eye: [['path', { d: 'M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z' }], ['circle', { cx: '12', cy: '12', r: '2.5' }]],
    plus: [['path', { d: 'M12 5v14M5 12h14' }]], search: [['circle', { cx: '11', cy: '11', r: '7' }], ['path', { d: 'm20 20-4-4' }]],
    send: [['path', { d: 'm22 2-7 20-4-9-9-4Z' }], ['path', { d: 'M22 2 11 13' }]],
    logout: [['path', { d: 'M10 17l5-5-5-5' }], ['path', { d: 'M15 12H3' }], ['path', { d: 'M21 19V5a2 2 0 0 0-2-2h-5' }]],
    shield: [['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z' }], ['path', { d: 'm9 12 2 2 4-4' }]],
  }
  for (const [tag, attributes] of paths[name] ?? []) {
    const child = document.createElementNS('http://www.w3.org/2000/svg', tag)
    for (const [key, value] of Object.entries(attributes)) child.setAttribute(key, value)
    element.append(child)
  }
  return element
}
const brand = (light = false) => node('div', { className: `brand ${light ? 'brand-light' : 'brand-dark'}` }, [node('span', { className: 'brand-mark' }, [svg('lock', 17)]), ' cipher'])
const avatar = (username: string) => node('span', { className: 'avatar' }, [username.slice(0, 2).toUpperCase()])
const errorText = (error: unknown, selector = '#form-error') => { const element = document.querySelector<HTMLParagraphElement>(selector); if (element) element.textContent = error instanceof Error ? error.message : 'Error inesperado.' }

const keyDatabase = indexedDB.open('cipher-keys', 1)
keyDatabase.onupgradeneeded = () => keyDatabase.result.createObjectStore('keys', { keyPath: 'id' })
const keysReady = new Promise<IDBDatabase>((resolve, reject) => { keyDatabase.onsuccess = () => resolve(keyDatabase.result); keyDatabase.onerror = () => reject(keyDatabase.error) })
async function storeKeys(keys: StoredKeys) { const database = await keysReady; await new Promise<void>((resolve, reject) => { const request = database.transaction('keys', 'readwrite').objectStore('keys').put(keys); request.onsuccess = () => resolve(); request.onerror = () => reject(request.error) }) }
async function loadKeys(id: number) { const database = await keysReady; return new Promise<StoredKeys | undefined>((resolve, reject) => { const request = database.transaction('keys').objectStore('keys').get(id); request.onsuccess = () => resolve(request.result as StoredKeys | undefined); request.onerror = () => reject(request.error) }) }

async function newIdentity() {
  const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const signing = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])
  const publicKey = b64(await crypto.subtle.exportKey('spki', ecdh.publicKey))
  const signingPublicKey = b64(await crypto.subtle.exportKey('spki', signing.publicKey))
  const publicKeySignature = b64(await crypto.subtle.sign({ name: 'Ed25519' }, signing.privateKey, buffer(bytes(publicKey))))
  return { ecdhPrivateKey: ecdh.privateKey, signingPrivateKey: signing.privateKey, publicKey, signingPublicKey, publicKeySignature }
}
async function verifyContact(contact: Contact) {
  const signing = await crypto.subtle.importKey('spki', buffer(bytes(contact.signingPublicKey)), { name: 'Ed25519' }, false, ['verify'])
  const valid = await crypto.subtle.verify({ name: 'Ed25519' }, signing, buffer(bytes(contact.publicKeySignature)), buffer(bytes(contact.publicKey)))
  if (!valid) throw new Error('La identidad de este usuario no tiene una firma válida.')
  const trustKey = `cipher-trust-${contact.username}`
  const pinned = localStorage.getItem(trustKey)
  if (pinned && pinned !== contact.signingPublicKey) throw new Error('La clave de seguridad cambió. Compara la huella antes de continuar.')
  if (!pinned) localStorage.setItem(trustKey, contact.signingPublicKey)
  return contact
}
async function hkdfKey(sharedSecret: ArrayBuffer, salt: Uint8Array, usage: KeyUsage[]) {
  const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: buffer(salt), info: textEncoder.encode('cipher-message-v1') }, material, { name: 'AES-GCM', length: 256 }, false, usage)
}
async function encryptFor(text: string, recipientPublicKey: string): Promise<Envelope> {
  const recipient = await crypto.subtle.importKey('spki', buffer(bytes(recipientPublicKey)), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipient }, ephemeral.privateKey, 256)
  const salt = crypto.getRandomValues(new Uint8Array(16)); const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buffer(iv) }, await hkdfKey(sharedSecret, salt, ['encrypt']), textEncoder.encode(text))
  return { ciphertext: b64(ciphertext), iv: b64(iv), salt: b64(salt), ephemeralPublicKey: b64(await crypto.subtle.exportKey('spki', ephemeral.publicKey)) }
}
async function decryptMessage(message: Message) {
  if (!privateKey || !identity) throw new Error('La clave privada no está desbloqueada.')
  const sender = message.senderId === identity.id
  const envelope: Envelope = { ciphertext: (sender ? message.senderCiphertext : message.recipientCiphertext) ?? '', iv: (sender ? message.senderIv : message.recipientIv) ?? '', salt: (sender ? message.senderSalt : message.recipientSalt) ?? '', ephemeralPublicKey: (sender ? message.senderEphemeralPublicKey : message.recipientEphemeralPublicKey) ?? '' }
  if (!envelope.ciphertext || !envelope.iv || !envelope.salt || !envelope.ephemeralPublicKey) throw new Error('Mensaje antiguo no compatible.')
  const ephemeral = await crypto.subtle.importKey('spki', buffer(bytes(envelope.ephemeralPublicKey)), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: ephemeral }, privateKey, 256)
  const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buffer(bytes(envelope.iv)) }, await hkdfKey(sharedSecret, bytes(envelope.salt), ['decrypt']), buffer(bytes(envelope.ciphertext)))
  return new TextDecoder().decode(clear)
}

function renderAuth(register = false) {
  const root = node('main', { className: 'auth-shell' })
  const visual = node('section', { className: 'auth-visual' }, [brand(true), node('div', { className: 'visual-copy' }, [node('div', { className: 'eyebrow' }, ['● Privacidad por diseño']), node('h1', {}, ['Tus conversaciones,', node('br'), node('em', {}, ['solo tuyas.'])]), node('p', {}, ['Mensajería privada con cifrado de extremo a extremo. Sin nombres reales, sin rastreo, sin ruido.'])]), node('div', { className: 'security-note' }, [svg('shield', 18), ' Cifrado ECDH + Ed25519 en tu dispositivo'])])
  const form = node('form', { id: 'auth-form', className: 'auth-form' })
  const username = node('input', { name: 'username', autocomplete: 'username', placeholder: 'tu_username', minlength: '3', maxlength: '20', required: true })
  const password = node('input', { name: 'password', type: 'password', autocomplete: register ? 'new-password' : 'current-password', placeholder: '••••••••', minlength: '8', required: true })
  const passwordWrap = node('div', { className: 'password-input' }, [password])
  const showPassword = node('button', { type: 'button', className: 'show-password', 'aria-label': 'Mostrar contraseña' }, [svg('eye', 17)])
  passwordWrap.append(showPassword)
  form.append(node('label', {}, ['Username', username]), node('label', {}, ['Contraseña', passwordWrap]))
  if (register) form.append(node('label', {}, ['Repite la contraseña', node('input', { name: 'confirmPassword', type: 'password', placeholder: '••••••••', minlength: '8', required: true })]))
  const error = node('p', { id: 'form-error', className: 'form-error' })
  form.append(error, node('button', { className: 'primary-button', type: 'submit' }, [register ? 'Crear cuenta ' : 'Iniciar sesión ', svg('arrow', 17)]))
  showPassword.addEventListener('click', () => { password.type = password.type === 'password' ? 'text' : 'password' })
  const switchButton = node('button', { id: 'switch-auth' }, [register ? 'Inicia sesión' : 'Regístrate'])
  switchButton.addEventListener('click', () => renderAuth(!register))
  const panel = node('section', { className: 'auth-panel' }, [node('div', { className: 'auth-form-wrap' }, [brand(), node('div', { className: 'auth-heading' }, [node('p', { className: 'form-kicker' }, [register ? 'Comienza en privado' : 'Bienvenido de nuevo']), node('h2', {}, [register ? 'Crea tu cuenta' : 'Inicia sesión']), node('p', {}, [register ? 'Solo necesitas un username y una contraseña.' : 'Accede a tus conversaciones seguras.'])]), form, node('p', { className: 'auth-switch' }, [register ? '¿Ya tienes una cuenta? ' : '¿Aún no tienes cuenta? ', switchButton])]), node('div', { className: 'auth-footer' }, ['', 'Privacidad · Seguridad'])])
  root.append(visual, panel); app.replaceChildren(root)
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    const data = new FormData(form); const name = String(data.get('username')).trim().toLowerCase(); const secret = String(data.get('password'))
    try {
      if (register && data.get('confirmPassword') !== secret) throw new Error('Las contraseñas no coinciden.')
      if (register) {
        const keys = await newIdentity()
        const created = await api<Identity>('/auth/register', json({ username: name, password: secret, publicKey: keys.publicKey, signingPublicKey: keys.signingPublicKey, publicKeySignature: keys.publicKeySignature }))
        await storeKeys({ id: created.id, privateKey: keys.ecdhPrivateKey, signingPrivateKey: keys.signingPrivateKey })
        identity = created; privateKey = keys.ecdhPrivateKey
      } else {
        const loggedIn = await api<Identity>('/auth/login', json({ username: name, password: secret }))
        const keys = await loadKeys(loggedIn.id)
        if (!keys) throw new Error('Esta cuenta no tiene sus claves privadas en este navegador. Regístrate de nuevo en este dispositivo.')
        identity = loggedIn; privateKey = keys.privateKey
        await verifyContact(loggedIn)
      }
      await renderDashboard()
    } catch (reason) { error.textContent = reason instanceof Error ? reason.message : 'No se pudo completar el registro.' }
  })
}

async function renderDashboard() {
  if (!identity) return
  const contacts = await api<Contact[]>('/users')
  const list = node('div', { className: 'conversation-list' })
  contacts.forEach((contact) => {
    const item = node('button', { className: 'conversation-item' }, [avatar(contact.username), node('span', { className: 'conversation-copy' }, [node('strong', {}, [contact.username]), node('small', {}, ['● En linea'])])])
    item.dataset.username = contact.username; item.addEventListener('click', async () => { try { const verified = await verifyContact(contact); await openChat(verified) } catch (reason) { errorText(reason) } }); list.append(item)
  })
  if (!contacts.length) list.append(node('div', { className: 'empty-list' }, ['✦', node('p', {}, ['Aún no hay usuarios']), node('small', {}, ['Comparte tu username para empezar.'])]))
  const search = node('input', { id: 'contact-search', placeholder: 'Buscar usuarios' })
  search.addEventListener('input', () => list.querySelectorAll<HTMLElement>('.conversation-item').forEach((item) => { item.hidden = !item.textContent!.toLowerCase().includes(search.value.toLowerCase()) }))
  const sidebar = node('aside', { className: 'sidebar' }, [node('div', { className: 'sidebar-head' }, [node('div', {}, [node('p', { className: 'section-label' }, ['Buzón privado']), node('h1', {}, ['Mensajes'])]), node('button', { className: 'new-message', 'aria-label': 'Nuevo mensaje' }, [svg('plus', 19)])]), node('div', { className: 'search-box' }, [svg('search', 17), search]), list, node('div', { className: 'sidebar-security' }, [svg('shield', 17), node('div', {}, [node('strong', {}, ['Sesión protegida']), node('small', {}, ['El servidor no recibe claves privadas.'])])])])
  const chatPanel = node('section', { className: 'chat-panel', id: 'chat-panel' })
  if (contacts[0]) await openChat(contacts[0], chatPanel)
  else chatPanel.append(node('div', { className: 'no-messages' }, [node('h3', {}, ['Este espacio es solo tuyo']), node('p', {}, ['Busca un username para iniciar una conversación cifrada.'])]))
  sidebar.querySelector('.new-message')?.addEventListener('click', () => showNewMessage(chatPanel))
  const topbar = node('header', { className: 'topbar' }, [brand(), node('div', { className: 'topbar-actions' }, [node('span', { className: 'online-dot' }), node('span', { className: 'topbar-username' }, [identity!.username]), node('button', { className: 'icon-button', 'aria-label': 'Cerrar sesión' }, [svg('logout', 18)] )])])
  topbar.querySelector('.icon-button')?.addEventListener('click', async () => { await api('/auth/logout', { method: 'POST' }); identity = null; privateKey = null; renderAuth() })
  app.replaceChildren(node('main', { className: 'app-shell' }, [topbar, node('div', { className: 'mobile-title' }, ['Mensajes']), node('div', { className: 'dashboard' }, [sidebar, chatPanel])]))
}

async function openChat(contact: Contact, target = document.querySelector<HTMLElement>('#chat-panel')) {
  if (!target) return
  const verified = await verifyContact(contact); const chat = await api<Chat>(`/messages/${encodeURIComponent(verified.username)}`)
  const header = node('div', { className: 'chat-header' }, [avatar(verified.username), node('div', {}, [node('h2', {}, [verified.username]), node('p', {}, ['● En linea'])]), node('div', { className: 'chat-header-lock' }, [svg('lock', 16), node('span', {}, [`Huella: ${verified.fingerprint}`])])])
  const area = node('div', { className: 'message-area' })
  if (!chat.messages.length) area.append(node('div', { className: 'no-messages' }, [node('h3', {}, ['Este espacio es solo tuyo']), node('p', {}, ['Los mensajes se cifran antes de salir de tu dispositivo.'])]))
  for (const message of chat.messages) {
    const bubble = node('div', { className: `message-bubble ${message.senderId === identity?.id ? 'mine' : ''}` }, [node('span', {}, ['Descifrando…'])])
    try { bubble.replaceChildren(node('span', {}, [await decryptMessage(message)])) } catch (reason) { bubble.replaceChildren(node('span', {}, [reason instanceof Error ? reason.message : 'No se pudo descifrar.'])) }
    area.append(node('div', { className: `message-row ${message.senderId === identity?.id ? 'mine' : ''}` }, [bubble, node('time', {}, [formatTime(message.sentAt)])]))
  }
  const composer = node('form', { className: 'composer', id: 'composer' }); const input = node('input', { name: 'message', maxlength: '500', placeholder: 'Escribe tu mensaje', autocomplete: 'off' }); composer.append(input, node('button', { type: 'submit', 'aria-label': 'Enviar mensaje' }, [svg('send', 18)]))
  composer.addEventListener('submit', async (event) => {
    event.preventDefault(); const text = input.value.trim(); if (!text || !identity) return
    try {
      const recipientEnvelope = await encryptFor(text, verified.publicKey); const senderEnvelope = await encryptFor(text, identity.publicKey)
      await api('/messages', json({ recipient: verified.username, senderCiphertext: senderEnvelope.ciphertext, senderIv: senderEnvelope.iv, senderSalt: senderEnvelope.salt, senderEphemeralPublicKey: senderEnvelope.ephemeralPublicKey, recipientCiphertext: recipientEnvelope.ciphertext, recipientIv: recipientEnvelope.iv, recipientSalt: recipientEnvelope.salt, recipientEphemeralPublicKey: recipientEnvelope.ephemeralPublicKey }))
      await openChat(verified, target); input.focus()
    } catch (reason) { errorText(reason) }
  })
  target.replaceChildren(header, area, composer, node('p', { className: 'encryption-caption' }, [svg('lock', 13), ` Cifrado E2E · Huella ${verified.fingerprint}`]))
}

async function showNewMessage(panel: HTMLElement) {
  const form = node('form', { id: 'new-message-form' }); const recipient = node('input', { name: 'recipient', placeholder: 'ej. sofia.r', required: true, minlength: '3' }); const message = node('textarea', { name: 'message', placeholder: 'Escribe tu mensaje aquí...', required: true, maxlength: '500' }); const error = node('p', { id: 'new-message-error', className: 'form-error' })
  form.append(node('label', {}, ['Nombre de usuario del destinatario', recipient]), node('label', {}, ['Mensaje', message]), node('button', { className: 'primary-button', type: 'submit' }, ['Enviar ', svg('send', 17)]), error)
  const view = node('div', { className: 'new-message-view' }, [node('button', { className: 'back-button', type: 'button' }, ['← Volver a mensajes']), node('div', { className: 'new-message-content' }, [node('p', { className: 'form-kicker' }, ['Nueva conversación']), node('h2', {}, ['Escribe a alguien']), node('p', {}, ['La identidad y la huella se verifican antes de cifrar.']), form])])
  view.querySelector('.back-button')?.addEventListener('click', () => renderDashboard())
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    try {
      if (!identity) throw new Error('Sesión no válida.')
      const name = String(new FormData(form).get('recipient')).trim().toLowerCase(); const clear = String(new FormData(form).get('message')).trim()
      const contact = (await api<Contact[]>(`/users?search=${encodeURIComponent(name)}`)).find((candidate) => candidate.username === name)
      if (!contact) throw new Error('Ese username no existe.')
      const verified = await verifyContact(contact); const recipientEnvelope = await encryptFor(clear, verified.publicKey); const senderEnvelope = await encryptFor(clear, identity.publicKey)
      await api('/messages', json({ recipient: name, senderCiphertext: senderEnvelope.ciphertext, senderIv: senderEnvelope.iv, senderSalt: senderEnvelope.salt, senderEphemeralPublicKey: senderEnvelope.ephemeralPublicKey, recipientCiphertext: recipientEnvelope.ciphertext, recipientIv: recipientEnvelope.iv, recipientSalt: recipientEnvelope.salt, recipientEphemeralPublicKey: recipientEnvelope.ephemeralPublicKey }))
      await renderDashboard()
    } catch (reason) { error.textContent = reason instanceof Error ? reason.message : 'No se pudo enviar.' }
  })
  panel.replaceChildren(view)
}

api<Identity>('/auth/me').then(async (value) => {
  identity = value
  const keys = await loadKeys(value.id)
  if (!keys) throw new Error('No hay claves privadas locales para esta sesión.')
  privateKey = keys.privateKey; await verifyContact(value); await renderDashboard()
}).catch(() => renderAuth())
