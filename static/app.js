// psh - WebSSH Proxy Frontend
// Main application entry point

import { Terminal } from '/static/xterm/xterm.esm.js';
import { FitAddon } from '/static/xterm/xterm-addon-fit.esm.js';

// HTML escape function to prevent XSS attacks
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Input validation functions
function validateHost(host) {
    // Allow letters, numbers, dots, hyphens, underscores, and IP addresses
    if (!host || host.length > 255) return false;
    return /^[a-zA-Z0-9._-]+$/.test(host);
}

function parseConnection(input) {
    let user = null;
    let host = null;
    let port = null;

    // Parse user@host:port
    const parts = input.split('@');
    if (parts.length === 2) {
        user = parts[0];
        const hostParts = parts[1].split(':');
        host = hostParts[0];
        if (hostParts.length === 2) {
            port = parseInt(hostParts[1], 10);
        }
    } else {
        const hostParts = input.split(':');
        host = hostParts[0];
        if (hostParts.length === 2) {
            port = parseInt(hostParts[1], 10);
        }
    }

    return { user, host, port };
}

function validatePort(port) {
    if (!port) return true;  // Optional
    const p = parseInt(port, 10);
    return !isNaN(p) && p > 0 && p <= 65535;
}

function validateUser(user) {
    if (!user) return true;  // Optional
    // Allow letters, numbers, underscores, hyphens
    return /^[a-zA-Z0-9_-]+$/.test(user);
}

// Application state
class PshApp {
    constructor() {
        // Token now stored in HttpOnly cookie, no need to manage in JS
        this.sessions = new Map();
        this.activeSessionId = null;

        // DOM elements
        this.tabBar = document.getElementById('tabBar');
        this.content = document.getElementById('content');
        this.welcome = document.getElementById('welcome');
        this.statusText = document.getElementById('statusText');
        this.connectionInfo = document.getElementById('connectionInfo');
        this.overlay = document.getElementById('overlay');
        this.connectionDialog = document.getElementById('connectionDialog');
        this.hostSelect = document.getElementById('hostSelect');
        this.hostInput = document.getElementById('hostInput');

        // Bind event handlers
        this.init();
    }

    // Debounce helper function
    debounce(fn, delay) {
        let timer = null;
        return (...args) => {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), delay);
        };
    }

    async init() {
        // Setup event listeners
        document.getElementById('addTabBtn').addEventListener('click', () => this.showConnectionDialog());
        document.getElementById('connectBtn').addEventListener('click', () => this.handleConnect());
        document.getElementById('cancelBtn').addEventListener('click', () => this.hideConnectionDialog());
        this.overlay.addEventListener('click', () => this.hideConnectionDialog());

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.onKeyDown(e));
        window.addEventListener('resize', () => this.onResize());

        // Token is stored in HttpOnly cookie, validate it via API call
        const valid = await this.validateToken();
        if (valid) {
            await this.loadHosts();
        } else {
            this.showLoginDialog();
        }
    }
    
    async validateToken() {
        try {
            const response = await fetch('/api/hosts', {
                credentials: 'include'  // Automatically send cookies
            });
            return response.ok;
        } catch {
            return false;
        }
    }
    
    showLoginDialog() {
        // Create login dialog
        const loginHtml = `
            <div class="login-dialog" id="loginDialog">
                <div class="dialog-title">Login to psh</div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-input" id="loginPassword" placeholder="Enter password">
                </div>
                <div class="button-group">
                    <button class="btn btn-primary" id="loginBtn">Login</button>
                </div>
                <div class="error-msg hidden" id="loginError"></div>
            </div>
        `;
        
        this.overlay.classList.add('active');
        this.overlay.insertAdjacentHTML('afterend', loginHtml);
        
        const loginBtn = document.getElementById('loginBtn');
        const passwordInput = document.getElementById('loginPassword');
        
        loginBtn.addEventListener('click', () => this.handleLogin());
        passwordInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.handleLogin();
        });
        passwordInput.focus();
    }
    
    async handleLogin() {
        const password = document.getElementById('loginPassword').value;
        const errorEl = document.getElementById('loginError');

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',  // Automatically receive and send cookies
                body: JSON.stringify({ password })
            });

            if (response.ok) {
                document.getElementById('loginDialog').remove();
                this.overlay.classList.remove('active');
                await this.loadHosts();
            } else {
                errorEl.textContent = 'Invalid password';
                errorEl.classList.remove('hidden');
            }
        } catch (e) {
            errorEl.textContent = 'Connection error';
            errorEl.classList.remove('hidden');
        }
    }
    
    async loadHosts() {
        try {
            const response = await fetch('/api/hosts', {
                credentials: 'include'  // Automatically send cookies
            });

            if (response.ok) {
                const hosts = await response.json();
                this.hostSelect.innerHTML = '<option value="">-- Select host --</option>';
                hosts.forEach(host => {
                    const option = document.createElement('option');
                    option.value = host.name;
                    option.textContent = `${host.name} (${host.user || 'user'}@${host.hostname}:${host.port})`;
                    this.hostSelect.appendChild(option);
                });
            } else {
                this.showGlobalError('Failed to Load Hosts',
                    `Server returned ${response.status}. Please refresh the page.`);
            }
        } catch (e) {
            console.error('Failed to load hosts:', e);
            this.showGlobalError('Connection Error',
                'Unable to connect to server. Please check your network.');
        }
    }
    
    showConnectionDialog() {
        this.overlay.classList.add('active');
        this.connectionDialog.classList.remove('hidden');
        this.hostInput.focus();
    }

    hideConnectionDialog() {
        this.overlay.classList.remove('active');
        this.connectionDialog.classList.add('hidden');
        this.hostInput.value = '';
        this.hostSelect.value = '';
    }

    async handleConnect() {
        let host = null;
        let user = null;
        let port = null;

        // Try manual input first
        const manual = this.hostInput.value.trim();
        if (manual) {
            const parsed = parseConnection(manual);
            host = parsed.host;
            user = parsed.user;
            port = parsed.port;
        } else {
            // Try select
            host = this.hostSelect.value || null;
        }

        if (!host) {
            this.showError('Please enter a host or select from list');
            return;
        }

        this.hideConnectionDialog();
        this.createTerminalSession(host, user, port);
    }
    
    createTerminalSession(host, user, port) {
        const sessionId = `session-${Date.now()}`;
        
        // Create tab
        const tab = document.createElement('div');
        tab.className = 'tab';
        tab.id = `tab-${sessionId}`;
        tab.innerHTML = `
            <span class="tab-title">${escapeHtml(host)}</span>
            <span class="tab-close">×</span>
        `;
        tab.addEventListener('click', (e) => {
            if (e.target.classList.contains('tab-close')) {
                this.closeSession(sessionId);
            } else {
                this.switchToSession(sessionId);
            }
        });
        this.tabBar.appendChild(tab);
        
        // Create terminal container
        const container = document.createElement('div');
        container.className = 'terminal-container';
        container.id = `container-${sessionId}`;
        this.content.appendChild(container);
        
        // Hide welcome
        if (this.welcome) {
            this.welcome.classList.remove('active');
        }
        
        // Initialize xterm
        const term = new Terminal({
            theme: {
                background: '#1e1e1e',
                foreground: '#d4d4d4',
                cursor: '#ffffff',
                cursorAccent: '#1e1e1e',
                selection: 'rgba(255, 255, 255, 0.3)',
                black: '#000000',
                red: '#cd3131',
                green: '#0dbc79',
                yellow: '#e5e510',
                blue: '#2472c8',
                magenta: '#bc3fbc',
                cyan: '#11a8cd',
                white: '#e5e5e5',
                brightBlack: '#666666',
                brightRed: '#f14c4c',
                brightGreen: '#23d18b',
                brightYellow: '#f5f543',
                brightBlue: '#3b8eea',
                brightMagenta: '#d670d6',
                brightCyan: '#29b8db',
                brightWhite: '#e5e5e5'
            },
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            fontSize: 14,
            cursorBlink: true,
            scrollback: 10000
        });
        
        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);
        term.open(container);
        fitAddon.fit();
        
        // Build WebSocket URL (token sent via cookie)
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/terminal`;

        // Use native WebSocket
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            term.writeln('\x1b[32mConnecting to ' + escapeHtml(host) + '...\x1b[0m');

            // Send connection request
            const connectMsg = {
                type: 'connect',
                host: host,
                user: user,
                port: port
            };
            ws.send(JSON.stringify(connectMsg));
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);

                switch (msg.type) {
                    case 'output':
                        // Decode base64
                        const data = atob(msg.data);
                        term.write(data);
                        break;
                    case 'connected':
                        term.writeln('\x1b[32mConnected!\x1b[0m');
                        this.updateStatus('Connected', `${escapeHtml(msg.user || 'user')}@${escapeHtml(msg.host)}`);
                        // Update session
                        const session = this.sessions.get(sessionId);
                        if (session) {
                            session.connected = true;
                            session.tab.querySelector('.tab-title').textContent = msg.host;
                        }
                        break;
                    case 'error':
                        term.writeln('\x1b[31mError: ' + escapeHtml(msg.message) + '\x1b[0m');
                        break;
                }
            } catch (e) {
                // Plain text output
                term.write(event.data);
            }
        };

        ws.onclose = () => {
            term.writeln('');
            term.writeln('\x1b[33mConnection closed.\x1b[0m');
            this.updateStatus('Disconnected', escapeHtml(host));
            const session = this.sessions.get(sessionId);
            if (session) {
                session.connected = false;
            }
        };

        ws.onerror = (error) => {
            term.writeln('\x1b[31mWebSocket error\x1b[0m');
            console.error('WebSocket error:', error);
        };
        
        // Handle terminal input
        term.onData((data) => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                    type: 'input',
                    data: btoa(data)  // Encode to base64
                }));
            }
        });
        
        // Store session
        this.sessions.set(sessionId, {
            id: sessionId,
            ws,
            term,
            fitAddon,
            container,
            tab,
            connected: false,
            host,
            user
        });
        
        // Switch to new session
        this.switchToSession(sessionId);

        // Resize handler with debounce
        const handleResize = this.debounce(() => {
            if (container.classList.contains('active')) {
                fitAddon.fit();
                const dims = fitAddon.proposeDimensions();
                if (ws.readyState === WebSocket.OPEN && dims) {
                    ws.send(JSON.stringify({
                        type: 'resize',
                        cols: dims.cols,
                        rows: dims.rows
                    }));
                }
            }
        }, 200);  // 200ms debounce

        const resizeObserver = new ResizeObserver(handleResize);
        resizeObserver.observe(container);

        this.sessions.get(sessionId).resizeObserver = resizeObserver;
    }
    
    switchToSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        
        // Deactivate current
        if (this.activeSessionId) {
            const current = this.sessions.get(this.activeSessionId);
            if (current) {
                current.tab.classList.remove('active');
                current.container.classList.remove('active');
            }
        }
        
        // Activate new
        session.tab.classList.add('active');
        session.container.classList.add('active');
        this.activeSessionId = sessionId;
        
        // Focus terminal and fit
        session.term.focus();
        session.fitAddon.fit();
        
        // Update status
        this.updateStatus(
            session.connected ? 'Connected' : 'Connecting',
            session.user ? `${session.user}@${session.host}` : session.host
        );
    }
    
    closeSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        
        // Close WebSocket
        if (session.ws) {
            session.ws.close();
        }
        
        // Dispose terminal
        session.term.dispose();
        
        // Disconnect resize observer
        if (session.resizeObserver) {
            session.resizeObserver.disconnect();
        }
        
        // Remove elements
        session.tab.remove();
        session.container.remove();
        
        // Remove from map
        this.sessions.delete(sessionId);
        
        // Switch to another session or show welcome
        if (this.activeSessionId === sessionId) {
            const nextSession = this.sessions.keys().next().value;
            if (nextSession) {
                this.switchToSession(nextSession);
            } else {
                this.activeSessionId = null;
                if (this.welcome) {
                    this.welcome.classList.add('active');
                }
                this.updateStatus('Ready', '');
            }
        }
    }
    
    updateStatus(status, info) {
        this.statusText.textContent = status;
        this.connectionInfo.textContent = info;
    }

    showGlobalError(title, message, duration = 5000) {
        // Create error notification
        const notification = document.createElement('div');
        notification.className = 'global-notification';
        notification.innerHTML = `
            <div class="notification-title">${escapeHtml(title)}</div>
            <div class="notification-message">${escapeHtml(message)}</div>
        `;

        document.body.appendChild(notification);

        // Auto-remove after duration
        setTimeout(() => {
            notification.remove();
        }, duration);
    }

    showError(message) {
        // Show error in connection dialog
        let errorEl = document.getElementById('connectionError');
        if (!errorEl) {
            errorEl = document.createElement('div');
            errorEl.id = 'connectionError';
            errorEl.className = 'error-msg';
            this.connectionDialog.appendChild(errorEl);
        }
        errorEl.textContent = message;
        errorEl.classList.remove('hidden');

        // Auto-hide after 3 seconds
        setTimeout(() => {
            errorEl.classList.add('hidden');
        }, 3000);
    }

    onResize() {
        this.sessions.forEach(session => {
            if (session.container.classList.contains('active')) {
                session.fitAddon.fit();
            }
        });
    }
    
    onKeyDown(e) {
        // Ctrl/Cmd + T: New tab
        if ((e.ctrlKey || e.metaKey) && e.key === 't') {
            e.preventDefault();
            this.showConnectionDialog();
        }
        // Ctrl/Cmd + W: Close tab
        if ((e.ctrlKey || e.metaKey) && e.key === 'w') {
            e.preventDefault();
            if (this.activeSessionId) {
                this.closeSession(this.activeSessionId);
            }
        }
        // Ctrl/Cmd + number: Switch tab
        if ((e.ctrlKey || e.metaKey) && e.key >= '1' && e.key <= '9') {
            e.preventDefault();
            const index = parseInt(e.key) - 1;
            const sessionIds = Array.from(this.sessions.keys());
            if (index < sessionIds.length) {
                this.switchToSession(sessionIds[index]);
            }
        }
    }
}

// Initialize app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => new PshApp());
} else {
    new PshApp();
}
