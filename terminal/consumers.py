import json
import pty
import os
import termios
import struct
import fcntl
import select
import signal
from channels.generic.websocket import WebsocketConsumer
from django.contrib.auth.models import User
from asgiref.sync import async_to_sync

class TerminalConsumer(WebsocketConsumer):
    def connect(self):
        """建立连接时的处理"""
        if not self.scope['user'].is_authenticated:
            self.close()
            return
            
        self.accept()
        
        try:
            # 创建伪终端
            self.master_fd, slave_fd = pty.openpty()
            self.shell_pid = os.fork()
            
            if self.shell_pid == 0:  # 子进程
                os.close(self.master_fd)
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                os.close(slave_fd)
                
                # 设置环境变量
                env = dict(os.environ)
                env['TERM'] = 'xterm'
                env['PATH'] = f"{env.get('PATH', '')}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                env['SHELL'] = '/bin/bash'
                env['HOME'] = os.path.expanduser('~')
                
                # 执行shell
                try:
                    os.execvpe('/bin/bash', ['/bin/bash'], env)
                except:
                    try:
                        os.execvpe('/bin/sh', ['/bin/sh'], env)
                    except:
                        os._exit(1)
            else:  # 父进程
                os.close(slave_fd)
                # 设置非阻塞模式
                fcntl.fcntl(self.master_fd, fcntl.F_SETFL, os.O_NONBLOCK)
                
                # 设置初始终端大小
                self.resize_pty(24, 80)
                
        except Exception as e:
            self.send(json.dumps({
                'type': 'output',
                'data': f'\r\n\x1b[31m错误: {str(e)}\x1b[0m\r\n'
            }))
            self.close()

    def disconnect(self, close_code):
        """断开连接时的处理"""
        try:
            # 发送 SIGTERM 信号给shell进程
            os.kill(self.shell_pid, signal.SIGTERM)
            # 等待一段时间
            try:
                os.waitpid(self.shell_pid, os.WNOHANG)
            except:
                pass
            # 如果进程还在运行，强制结束
            try:
                os.kill(self.shell_pid, signal.SIGKILL)
                os.waitpid(self.shell_pid, 0)
            except:
                pass
        except:
            pass
            
        try:
            os.close(self.master_fd)
        except:
            pass

    def receive(self, text_data):
        """接收前端消息的处理"""
        try:
            data = json.loads(text_data)
            
            if data['type'] == 'input':
                # 发送输入到终端
                os.write(self.master_fd, data['data'].encode())
            elif data['type'] == 'resize':
                # 调整终端大小
                self.resize_pty(data['rows'], data['cols'])
                
            # 读取终端输出
            self.read_output()
                
        except Exception as e:
            self.send(json.dumps({
                'type': 'output',
                'data': f'\r\n\x1b[31m错误: {str(e)}\x1b[0m\r\n'
            }))

    def resize_pty(self, rows, cols):
        """调整终端大小"""
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        except:
            pass

    def read_output(self):
        """读取终端输出"""
        try:
            while True:
                r, w, e = select.select([self.master_fd], [], [], 0)
                if not r:
                    break
                    
                output = os.read(self.master_fd, 1024)
                if output:
                    # 尝试解码输出
                    try:
                        decoded = output.decode()
                    except UnicodeDecodeError:
                        decoded = output.decode(errors='replace')
                        
                    self.send(json.dumps({
                        'type': 'output',
                        'data': decoded
                    }))
                else:
                    # 如果没有输出，可能是shell已经退出
                    raise EOFError("Shell terminated")
                    
        except (OSError, IOError) as e:
            if e.errno == 5:  # Input/output error, 通常是终端已关闭
                self.close()
            elif e.errno != 11:  # 11 是 EAGAIN，表示暂时没有数据可读
                raise
        except EOFError:
            self.close() 