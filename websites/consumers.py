import json
import pty
import os
import termios
import struct
import fcntl
import select
from channels.generic.websocket import WebsocketConsumer
from threading import Thread
from django.contrib.auth.models import User
from asgiref.sync import async_to_sync
from .models import TerminalSession

class TerminalConsumer(WebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.terminal = None
        self.pid = None
        self.fd = None

    def connect(self):
        if not self.scope['user'].is_authenticated:
            self.close()
            return
            
        session_id = self.scope['query_string'].decode().split('=')[1]
        try:
            self.terminal_session = TerminalSession.objects.get(
                session_id=session_id,
                user=self.scope['user'],
                status='active'
            )
        except TerminalSession.DoesNotExist:
            self.close()
            return
            
        self.accept()
        
        # 创建伪终端
        self.pid, self.fd = pty.fork()
        
        if self.pid == 0:  # 子进程
            shell = os.environ.get('SHELL', '/bin/bash')
            os.execvp(shell, [shell])
        else:  # 父进程
            self.terminal_session.pid = self.pid
            self.terminal_session.save()
            Thread(target=self.read_output, daemon=True).start()

    def disconnect(self, close_code):
        if hasattr(self, 'terminal_session'):
            self.terminal_session.status = 'closed'
            self.terminal_session.save()
        
        if self.pid:
            try:
                os.kill(self.pid, 9)
            except OSError:
                pass
        if self.fd:
            try:
                os.close(self.fd)
            except OSError:
                pass

    def receive(self, text_data):
        try:
            data = json.loads(text_data)
            if data['type'] == 'terminal_input':
                # 写入终端
                os.write(self.fd, data['input'].encode())
            elif data['type'] == 'resize':
                # 调整终端大小
                self.resize_terminal(data.get('rows', 24), data.get('cols', 80))
        except Exception as e:
            print(f"Error in receive: {str(e)}")

    def read_output(self):
        """读取终端输出"""
        max_read_bytes = 1024 * 20
        while True:
            try:
                ready, _, _ = select.select([self.fd], [], [], 0.1)
                if ready:
                    output = os.read(self.fd, max_read_bytes)
                    if output:
                        # 发送到客户端
                        self.send(json.dumps({
                            'type': 'terminal_output',
                            'output': output.decode(errors='replace')
                        }))
                    else:
                        break
            except (OSError, IOError):
                break
            except Exception as e:
                print(f"Error in read_output: {str(e)}")
                break
        self.close()

    def resize_terminal(self, rows, cols):
        """调整终端大小"""
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                       struct.pack("HHHH", rows, cols, 0, 0))
        except (OSError, IOError) as e:
            print(f"Error resizing terminal: {str(e)}") 