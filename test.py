import json
import os
import queue
import random
import subprocess
from datetime import datetime
from io import TextIOWrapper
from queue import Queue
from threading import Thread

from cipher.asymmetry import CipherDict as ACipherDict
from cipher.symmetry import CipherDict as SCipherDict
from digest.baser import BaseDict
from digest.hasher import HashDict
from main import ExecuteDict

content = "床前明月光，疑是地上霜。举头望明月，低头思故乡"

output_console = True
message_queue = Queue()
t_thead = None
t_output = None
t_running = True

def print_output_queue():
    global message_queue, t_output
    if isinstance(t_output, TextIOWrapper):
        while t_running or not message_queue.empty():
            try:
                message = message_queue.get(timeout=3)  # 设置超时时间，防止永远等待
                t_output.write(message)
                message_queue.task_done()
            except queue.Empty:
                pass
        t_output.close()


def print_output(*args, force_output=False):
    global output_console
    if output_console or force_output:
        print(*args)
    else:
        global t_thead, t_output, message_queue
        if t_thead is None:
            dir_path = os.path.join('build', 'intermediates')
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            t_output = open(os.path.join(dir_path, f'{datetime.now().timestamp()}.txt'), 'a', encoding='utf-8')
            t_thead = Thread(target=print_output_queue)
            t_thead.start()
        for arg in args:
            message_queue.put(arg)

if __name__ == '__main__':
    base_call = [os.path.join('.venv', 'Scripts', 'python'), 'main.py']

    def execute_command(*args):
        print_output(f'Executing command: {" ".join(args[2:])}', force_output=True)
        try:
            return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
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
            except Exception:
                pass

    start_time = datetime.now()

    for way in ExecuteDict.keys():
        way_call = base_call + ['-w', way]
        if way == 'hash':
            for algorithm in HashDict.keys():
                hash_call = way_call + ['-a', algorithm, content]
                if algorithm in ('shake128', 'shake256'):
                    hash_call = hash_call + ['-l', f'{random.randint(16, 64)}']
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

                def sci_decode(upper_call):
                    for m in ('ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'eax'):
                        common_decode(upper_call + ['-m', m, '-t'])

                if algorithm == 'des':
                    sci_decode(algorithm_call)
                else:
                    for bit in ('128', '192', '256') if algorithm == 'aes' else ('128', '192'):
                        sci_decode(algorithm_call + ['-l', bit])

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

    print_output(f'{(datetime.now() - start_time).total_seconds() * 1000} MS', force_output=True)

    if isinstance(t_thead, Thread):
        t_running = False
        t_thead.join()

