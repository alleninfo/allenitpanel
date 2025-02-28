import json
from channels.generic.websocket import AsyncWebsocketConsumer
from .terminal_manager import TerminalManager

class TerminalConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        """处理WebSocket连接"""
        self.session_id = self.scope['url_route']['kwargs']['session_id']
        self.terminal = TerminalManager.get_instance(self.session_id)
        
        await self.accept()
        
        # 启动终端并开始读取输出
        self.read_task = await self.terminal.start_reading(self)

    async def disconnect(self, close_code):
        """处理WebSocket断开连接"""
        TerminalManager.remove_instance(self.session_id)

    async def receive(self, text_data):
        """处理接收到的数据"""
        try:
            # 尝试解析为JSON（用于调整终端大小）
            try:
                data = json.loads(text_data)
                if data.get('type') == 'resize':
                    self.terminal.resize(data['rows'], data['cols'])
                    return
            except json.JSONDecodeError:
                pass
            
            # 处理普通终端输入
            self.terminal.write(text_data)
            
        except Exception as e:
            print(f"Error in receive: {e}")
            await self.close() 