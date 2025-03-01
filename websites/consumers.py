import json
from channels.generic.websocket import AsyncWebsocketConsumer
import asyncio
import pty
import os
import termios
import struct
import fcntl
import subprocess

class TerminalConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.terminal_id = self.scope['url_route']['kwargs']['terminal_id']
        self.group_name = f'terminal_{self.terminal_id}'
        
        # 加入终端组
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        
        # 创建伪终端
        self.master_fd, self.slave_fd = pty.openpty()
        # 设置终端大小
        self.set_terminal_size(24, 80)
        
        # 启动shell进程
        self.shell = subprocess.Popen(
            'bash',
            preexec_fn=os.setsid,
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            universal_newlines=True
        )
        
        # 设置master_fd为非阻塞模式
        flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        
        await self.accept()
        
        # 启动读取输出的任务
        self.read_task = asyncio.create_task(self.read_output())

    def set_terminal_size(self, rows, cols):
        size = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(self.slave_fd, termios.TIOCSWINSZ, size)

    async def read_output(self):
        while True:
            try:
                data = os.read(self.master_fd, 1024)
                if data:
                    await self.send(text_data=data.decode())
            except (OSError, BlockingIOError):
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"读取终端输出错误: {str(e)}")
                break

    async def disconnect(self, close_code):
        # 停止读取任务
        if hasattr(self, 'read_task'):
            self.read_task.cancel()
            
        # 关闭终端和进程
        if hasattr(self, 'shell'):
            self.shell.terminate()
            try:
                self.shell.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.shell.kill()
        
        if hasattr(self, 'master_fd'):
            os.close(self.master_fd)
        if hasattr(self, 'slave_fd'):
            os.close(self.slave_fd)
        
        # 离开终端组
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            if 'input' in data:
                os.write(self.master_fd, data['input'].encode())
            elif 'resize' in data:
                size = data['resize']
                self.set_terminal_size(size['rows'], size['cols'])
        except json.JSONDecodeError:
            # 如果不是JSON，则认为是普通输入
            os.write(self.master_fd, text_data.encode())
        except Exception as e:
            print(f"处理终端输入错误: {str(e)}") 