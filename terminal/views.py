from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
import threading
import queue
import time
import json
import os
import pty
import select
import struct
import fcntl
import termios
import errno

class Terminal:
    def __init__(self):
        self.fd = None
        self.pid = None
        self.output_queue = queue.Queue()
        self.running = False

    def start(self):
        """启动终端进程"""
        if self.running:
            return False

        try:
            # 创建伪终端
            pid, fd = pty.fork()
            
            if pid == 0:  # 子进程
                # 设置环境变量
                env = dict(os.environ)
                env['TERM'] = 'xterm-256color'
                env['COLORTERM'] = 'truecolor'
                env['LANG'] = 'en_US.UTF-8'
                env['LC_ALL'] = 'en_US.UTF-8'
                env['HOME'] = os.path.expanduser('~')
                env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
                
                try:
                    os.execvpe('/bin/bash', ['/bin/bash', '--login'], env)
                except:
                    os.execvpe('/bin/sh', ['/bin/sh', '-l'], env)
            else:  # 父进程
                self.pid = pid
                self.fd = fd
                
                # 设置非阻塞模式
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
                
                # 启动读取线程
                self.running = True
                threading.Thread(target=self._read_output, daemon=True).start()
                
                return True
                
        except Exception as e:
            print(f"终端启动错误: {str(e)}")
            return False

    def write(self, data):
        """向终端写入数据"""
        if self.fd:
            try:
                os.write(self.fd, data.encode())
            except:
                pass

    def read(self, timeout=0.1):
        """从终端读取数据"""
        try:
            return self.output_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def resize(self, rows, cols):
        """调整终端大小"""
        if self.fd:
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)
            except:
                pass

    def _read_output(self):
        """读取终端输出的后台线程"""
        while self.running and self.fd:
            try:
                r, w, e = select.select([self.fd], [], [], 0.1)
                if not r:
                    continue
                    
                data = os.read(self.fd, 8192)
                if data:
                    self.output_queue.put(data.decode(errors='replace'))
                else:
                    break
            except OSError as e:
                if e.errno != errno.EAGAIN:
                    break
            except:
                break
        self.running = False

    def stop(self):
        """停止终端"""
        self.running = False
        if self.pid:
            try:
                os.kill(self.pid, 15)  # SIGTERM
                os.waitpid(self.pid, 0)
            except:
                pass
        if self.fd:
            try:
                os.close(self.fd)
            except:
                pass

# 存储所有终端会话
terminals = {}

@login_required
def terminal(request):
    """终端页面"""
    return render(request, 'terminal/index.html')

@login_required
def terminal_start(request):
    """启动新终端"""
    term = Terminal()
    if term.start():
        terminal_id = str(time.time())
        terminals[terminal_id] = term
        return JsonResponse({'terminal_id': terminal_id})
    return JsonResponse({'error': '终端启动失败'}, status=500)

@login_required
def terminal_stop(request, terminal_id):
    """停止终端"""
    if terminal_id in terminals:
        terminals[terminal_id].stop()
        del terminals[terminal_id]
    return JsonResponse({'status': 'success'})

@login_required
def terminal_write(request, terminal_id):
    """向终端写入数据"""
    if terminal_id in terminals:
        data = request.POST.get('data', '')
        terminals[terminal_id].write(data)
    return JsonResponse({'status': 'success'})

@login_required
def terminal_read(request, terminal_id):
    """从终端读取数据"""
    if terminal_id in terminals:
        data = terminals[terminal_id].read()
        if data:
            return JsonResponse({'data': data})
    return JsonResponse({'data': ''})

@login_required
def terminal_resize(request, terminal_id):
    """调整终端大小"""
    if terminal_id in terminals:
        rows = int(request.POST.get('rows', 24))
        cols = int(request.POST.get('cols', 80))
        terminals[terminal_id].resize(rows, cols)
    return JsonResponse({'status': 'success'})
