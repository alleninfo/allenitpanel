import os
import signal
import asyncio
import json
import subprocess
import pty
import fcntl
import termios
import struct
from typing import Dict, Optional

class TerminalManager:
    _instances: Dict[str, 'TerminalManager'] = {}
    
    @classmethod
    def get_instance(cls, session_id: str) -> 'TerminalManager':
        if session_id not in cls._instances:
            cls._instances[session_id] = cls(session_id)
        return cls._instances[session_id]
    
    @classmethod
    def remove_instance(cls, session_id: str):
        if session_id in cls._instances:
            instance = cls._instances[session_id]
            instance.terminate()
            del cls._instances[session_id]
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.process = None
        self.read_task = None
        self.websocket = None
        self.master_fd = None
        self.slave_fd = None
    
    def start(self):
        """启动终端进程"""
        if not self.process:
            try:
                # 创建伪终端
                self.master_fd, self.slave_fd = pty.openpty()
                
                # 设置终端属性
                attrs = termios.tcgetattr(self.slave_fd)
                attrs[3] = attrs[3] | termios.ECHO | termios.ICANON  # 启用回显和规范模式
                termios.tcsetattr(self.slave_fd, termios.TCSANOW, attrs)
                
                # 启动bash进程
                self.process = subprocess.Popen(
                    ['/bin/bash', '--login'],  # 使用login shell
                    stdin=self.slave_fd,
                    stdout=self.slave_fd,
                    stderr=self.slave_fd,
                    env={
                        'TERM': 'xterm-256color',
                        'PATH': os.environ.get('PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'),
                        'HOME': '/root',
                        'USER': 'root',
                        'SHELL': '/bin/bash',
                        'PWD': '/root',
                        'PS1': '\\u@\\h:\\w\\$ '  # 设置提示符
                    },
                    preexec_fn=os.setsid,  # 创建新的进程组
                    close_fds=False  # 保持文件描述符打开
                )
                
                # 设置终端大小
                self.resize(80, 24)
                
                # 发送初始命令
                self.write('export PS1="\\u@\\h:\\w\\$ "\n')  # 确保设置提示符
                self.write('cd /root\n')
                self.write('clear\n')
                
            except Exception as e:
                print(f"Error starting terminal: {e}")
                self.cleanup()
                raise
    
    def resize(self, cols: int, rows: int):
        """调整终端大小"""
        if self.master_fd:
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            except Exception as e:
                print(f"Error resizing terminal: {e}")
    
    def write(self, data: str):
        """向终端写入数据"""
        if self.master_fd:
            try:
                os.write(self.master_fd, data.encode())
            except Exception as e:
                print(f"Error writing to terminal: {e}")
    
    def cleanup(self):
        """清理资源"""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=1)
            except:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except:
                    pass
            self.process = None
        
        for fd in [self.master_fd, self.slave_fd]:
            if fd is not None:
                try:
                    os.close(fd)
                except:
                    pass
        self.master_fd = None
        self.slave_fd = None
    
    def terminate(self):
        """终止终端进程"""
        self.cleanup()
        if self.read_task:
            try:
                self.read_task.cancel()
            except Exception as e:
                print(f"Error canceling read task: {e}")
            self.read_task = None
    
    async def start_reading(self, websocket):
        """开始读取终端输出"""
        try:
            self.websocket = websocket
            if not self.process:
                self.start()
            
            async def read_output():
                try:
                    while True:
                        if not self.process or self.process.poll() is not None:
                            break
                        
                        data = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: os.read(self.master_fd, 1024)
                        )
                        
                        if not data:
                            break
                        
                        if self.websocket and not self.websocket.closed:
                            await self.websocket.send(data.decode(errors='replace'))
                except Exception as e:
                    print(f"Error reading from terminal: {e}")
                finally:
                    self.terminate()
            
            self.read_task = asyncio.create_task(read_output())
            return self.read_task
            
        except Exception as e:
            print(f"Error in start_reading: {e}")
            self.terminate()
            raise 