import queue
import subprocess
import os
import json
from datetime import datetime
from queue import Queue
from threading import Thread

from main import ExecuteDict
from digest.hasher import HashDict
from digest.baser import BaseDict
from cipher.symmetry import CipherDict as SCipherDict
from cipher.asymmetry import CipherDict as ACipherDict

content = "床前明月光，疑是地上霜。举头望明月，低头思故乡"

output_console = True
message_queue = Queue()
t_thead = None
t_output = None
t_running = True


def print_output_queue():
    global message_queue, t_output
    while t_running or not message_queue.empty():
        try:
            message = message_queue.get(timeout=3)  # 设置超时时间，防止永远等待
            t_output.write(message.encode('utf-8'))
            message_queue.task_done()
        except any:
            pass

    t_output.close()

def print_output(*args):
    global output_console
    if output_console:
        print(*args)
    else:
        global t_thead, t_output, message_queue
        if t_thead is None:
            dir_path = os.path.dirname(os.path.join('build', 'intermediates'))
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            t_output = open(os.path.join(dir_path, f'{datetime.now().timestamp()}.txt'), 'a')
            t_thead = Thread(target=print_output_queue)
            t_thead.start()
        for arg in args:
            message_queue.put(arg)

if __name__ == '__main__':
    base_call = [os.path.join('.venv', 'Scripts', 'python'), 'main.py']

    def execute_command(*args):
        print_output(f'Executing command: {" ".join(args[2:])}')
        try:
            return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            print_output(f'Command failed with return code {e.returncode}')
            print_output(e.output)
            return None

    def common_decode(upper_call):
        middle_ware = execute_command(*(upper_call + ['e', content]))
        if middle_ware is not None:
            print_output(middle_ware)
            try:
                print_output(execute_command(*(upper_call + ['d', json.loads(middle_ware)['cipher_sum']])))
            except any:
                pass

    for way in ExecuteDict.keys():
        way_call = base_call + ['-w', way]
        if way == 'hash':
            for algorithm in HashDict.keys():
                hash_call = way_call + ['-a', algorithm, content]
                if algorithm in ('shake128', 'shake256'):
                    hash_call = hash_call + ['-l', '16']
                print_output(execute_command(*hash_call))
        elif way == 'base':
            for algorithm in BaseDict.keys():
                baser_call = way_call + ['-a', algorithm, '-t']
                middleware = execute_command(*(baser_call + ['e', content]))
                if middleware is not None:
                    print_output(middleware)
                    print_output(execute_command(*(baser_call + ['d', json.loads(middleware)['output']])))
        elif way == 'sci':
            for algorithm in SCipherDict.keys():
                algorithm_call = way_call + ['-a', algorithm]
                for bit in ['128', '192', '256']:
                    bit_call = algorithm_call + ['-l', bit]
                    for mode in ('ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'eax'):
                        mode_call = bit_call + ['-m', mode, '-t']
                        common_decode(mode_call)
        elif way == 'aci':
            for algorithm in ACipherDict.keys():
                algorithm_call = way_call + ['-a', algorithm]
                for l in ('1024', '2048', '3072'):
                    l_call = algorithm_call + ['-l', l]
                    for mode in ('oaep', 'v1.5'):
                        mode_call = l_call + ['-m', mode]
                        for signature in ('oaep', 'v1.5'):
                            signature_call = mode_call + ['-sm', signature, '-pwd', '1314', '-t']
                            common_decode(signature_call)

    if t_thead is not None:
        t_running = False
        t_thead.join()