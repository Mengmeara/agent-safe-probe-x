# app/services/streams.py
import os
import json
import time
from flask import Response, stream_with_context
from app.services.db import get_task_from_db

def stream_task_logs_response(task_id: str) -> Response:
    """
    构造 SSE Response，流式推送日志内容。
    逻辑与原 server.py /logs-stream 保持一致。
    """
    def generate():
        try:
            db_task = get_task_from_db(task_id)
            if not db_task:
                yield f"data: {json.dumps({'error': '任务不存在'})}\n\n"
                return

            log_file = (db_task.get('config') or {}).get('log_file') or ''
            if not log_file or not os.path.exists(log_file):
                yield f"data: {json.dumps({'error': '日志文件不存在'})}\n\n"
                return

            last_size = 0

            # 若任务已完成，直接输出完整日志并结束
            if db_task.get('status') == 'completed':
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    yield f"data: {json.dumps({'content': content, 'complete': True})}\n\n"
                return

            # 持续推送增量
            while True:
                if os.path.exists(log_file):
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        new_content = f.read()
                        if new_content:
                            yield f"data: {json.dumps({'content': new_content})}\n\n"
                            last_size = f.tell()

                # 任务完成时退出循环
                db_task = get_task_from_db(task_id)
                if db_task and db_task.get('status') in ['completed', 'failed']:
                    break

                time.sleep(0.5)
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
