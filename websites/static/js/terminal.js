class TerminalManager {
    constructor(sessionId, container) {
        this.sessionId = sessionId;
        this.container = container;
        
        // 创建终端实例
        this.term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            theme: {
                background: '#1e1e1e',
                foreground: '#ffffff',
                cursor: '#ffffff',
                selection: 'rgba(255, 255, 255, 0.3)',
                black: '#000000',
                red: '#e06c75',
                green: '#98c379',
                yellow: '#d19a66',
                blue: '#61afef',
                magenta: '#c678dd',
                cyan: '#56b6c2',
                white: '#abb2bf'
            },
            allowTransparency: true,
            scrollback: 1000,
            convertEol: true,
            cols: 80,
            rows: 24,
            cursorStyle: 'block',
            bellStyle: 'sound',
            screenReaderMode: false
        });

        // 打开终端
        this.term.open(this.container);
        
        // 连接WebSocket
        this.connect();
        
        // 初始化完成后聚焦终端
        setTimeout(() => {
            this.term.focus();
            this.term.write('\x1b[?25h');  // 显示光标
        }, 100);
    }

    connect() {
        // 构建 WebSocket URL
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/terminal/${this.sessionId}/`;
        
        if (this.ws) {
            this.ws.close();
        }
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            
            // 监听终端输入
            this.term.onData(data => {
                if (this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(data);
                }
            });
        };
        
        this.ws.onmessage = (event) => {
            if (event.data) {
                this.term.write(event.data);
            }
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.term.write('\r\n\x1B[1;31m连接已断开，3秒后重新连接...\x1B[0m\r\n');
            setTimeout(() => this.connect(), 3000);
        };
        
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.term.write('\r\n\x1B[1;31m连接错误\x1B[0m\r\n');
        };
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
        if (this.term) {
            this.term.dispose();
        }
    }
} 