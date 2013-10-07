#!/usr/bin/env python
#coding: utf-8
import BaseHTTPServer
import Queue
import SocketServer
import os
import re
import socket
import sys
import threading
import urllib
import urllib2

PORT = 8080
studentof = {} # a map between students and ips

class HeartBrokenError(Exception): pass

class AsyncFile(file):

    def __init__(self, fname):
        self.que = Queue.Queue()
        self.fname = fname
        th = threading.Thread(target=self._write)
        th.daemon = True # unsafe to be a daemon, need to find another way
        th.start()

    def write(self, data):
        self.que.put(data)

    def _write(self):
        with open(self.fname, 'a') as fout:
            while True:
                fout.write(self.que.get())
                fout.flush()

class Console(object):
    lock = threading.Lock()

    def __init__(self):
        # from the great Goagent
        self.__set_error_color = lambda: None
        self.__set_warning_color = lambda: None
        self.__set_debug_color = lambda: None
        self.__reset_color = lambda: None
        if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
            if os.name == 'nt':
                import ctypes
                SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
                GetStdHandle = ctypes.windll.kernel32.GetStdHandle
                self.__set_error_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
                self.__set_success_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x02)
                self.__reset_color = lambda: SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
            elif os.name == 'posix':
                self.__set_error_color = lambda: sys.stderr.write('\033[31m')
                self.__set_success_color = lambda: sys.stderr.write('\033[32m')
                self.__reset_color = lambda: sys.stderr.write('\033[0m')

    def error(self, msg):
        with self.lock:
            self.__set_error_color()
            sys.stderr.write(msg)
            self.__reset_color()
    
    def success(self, msg):
        with self.lock:
            self.__set_success_color()
            sys.stderr.write(msg)
            self.__reset_color()

    def info(self, msg):
        with self.lock:
            sys.stderr.write(msg)
console = Console()


class BoundedThreadingServer(SocketServer.ThreadingTCPServer, object):  # object for super
    allow_reuse_address = True
    daemon_threads = True
    maxconnections = 60

    def __init__(self, *args, **kwargs):
        super(BoundedThreadingServer, self).__init__(*args, **kwargs)
        self.sema = threading.Semaphore(self.maxconnections)

    def process_request(self, request, client_address):
        with self.sema:
            super(BoundedThreadingServer, self).process_request(
                    request, client_address)

class AuthenticationHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):

    server_version = "Schindler'List/0.1"
    result_fname = "Schindler'List.txt"

    rfn = os.path.join(os.path.dirname(__file__), result_fname)
    if os.path.exists(rfn):
        print 'Removing old data "%s"' % rfn
        os.unlink(rfn)
    fout = AsyncFile(rfn)

    def do_GET(self):
        ip = self.client_address[0]
        if ip in studentof:
            self.log_message('%s is naughty again', studentof[ip].sid)
            self.send_200('%s同学，你已经签到过了。' % studentof[ip].name)
            return
        if 'Authorization' not in self.headers:
            self.log_message('is online')
            self.send_401()
            return

        try:
            sid, passwd = self.parse_auth()
        except HeartBrokenError as e:
            self.log_message('Client sends "Authorization: %s", %s',
                    self.headers['Authorization'], e)
            self.send_401()
        except Exception as e:
            self.log_error('Client sends "Authorization: %s", %s',
                    self.headers['Authorization'], e)
            self.send_401()
        else:
            if len(sid) == 9:
                stu = UnderGraduateStudent(ip, sid, passwd)
            else:
                stu = GraduateStudent(ip, sid, passwd)
            try:
                stu.login()
            except HeartBrokenError as e:
                self.log_message('%s, %s', sid, e)
                self.send_401('Wrong username or password')
            except Exception as e:
                self.log_error('An error occured while %s is logging in "%s"', sid, e)
                self.send_401()
            else:
                self.fout.write('%s\t%-9s\t%-12s\t%s\n' % (self.log_date_time_string(),
                        stu.sid, stu.name, stu.ip))
                studentof[ip] = stu
                self.log_success('%s has successfully logged in', stu.sid)
                self.send_200('%s同学，签到成功！' % stu.name)
    
    do_HEAD = do_GET

    def send_200(self, body):
        body = '<h3>%s</h3>' % body
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header("Content-Length", str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def send_401(self, prompt='Authenticate yourself'):
        body = '<h3>%s</h3>' % prompt
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="%s"' % prompt)
        self.send_header("Content-Type", self.error_content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def parse_auth(self):
        basic, auth_enc = self.headers['Authorization'].split()
        assert basic.upper() == 'BASIC', 'authentication method is not supported'
        auth_dec = auth_enc.decode('base64')
        sid, colon, passwd = auth_dec.partition(':')
        assert colon == ':', 'assault maybe'  # the second will be the separator itself
        if not sid or not passwd:
            raise HeartBrokenError('empty student number or password')
        if not sid.isdigit():
            raise HeartBrokenError('student number must be an integer')
        self.log_message('%s is logging in', sid)
        return sid, passwd

    def log_request(self, code='-', size='-'):
        # override, otherwise it will spread bullshit all over my screen
        pass

    def log_error(self, format, *args):
        msg = self.format_message(format, *args)
        console.error(msg)

    def log_success(self, format, *args):
        msg = self.format_message(format, *args)
        console.success(msg)

    def log_message(self, format, *args):
        msg = self.format_message(format, *args)
        console.info(msg)

    def format_message(self, format, *args):
        return "%s - [%s] %s\n" % (self.log_date_time_string(),
                self.client_address[0], format%args)


class StudentMixin(object):
    ua = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Schindler'sList/0.1)"

    def __init__(self, ip, sid, passwd, name='张三'):  # name should be in utf-8
        self.ip = ip
        self.sid = sid
        self.passwd = passwd
        self.name = name
        # urllib2 is not thread safe, I'm glad to build it everytime
        cooker = urllib2.HTTPCookieProcessor()
        self.opener = urllib2.build_opener(cooker)
        self.opener.addheaders = [('User-Agent', self.ua)]

    def page_encoding(self, headers):
        return headers.getparam('charset') or 'GBK'

    def login(self):
        payload = self.post_data()
        resp = self.opener.open(self.login_url, payload)
        # I don't whether re is thread safe
        name_patt = re.compile(self.name_re, re.U)
        encoding = self.page_encoding(resp.info())
        match = name_patt.search(resp.read().decode(encoding))
        if not match:
            raise HeartBrokenError('wrong username or password')
        self.name = match.group(1).encode('utf-8')

class UnderGraduateStudent(StudentMixin):
    login_url = 'http://jw.dhu.edu.cn/dhu/login_zh.jsp'
    name_re = ur'欢迎<font color=blue><b>(\w+?)</b>'

    def post_data(self):
        return urllib.urlencode({
            'userName': self.sid,
            'userPwd': self.passwd,
        })

class GraduateStudent(StudentMixin):
    login_url = 'http://eidsbak.dhu.edu.cn:58080/amserver/UI/Login?goto=http://my.dhu.edu.cn/index7.jsp'
    name_re = ur'nowrap>(\w+?),欢迎进入本系统'

    def post_data(self):
        return urllib.urlencode({
            'Login.Token1': self.sid,
            'Login.Token2': self.passwd,
            'CheckCodePass': 'pass',
        })

def whats_my_sexual_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except:
        return '127.0.0.1'
    finally:
        s.close()

if __name__ == '__main__':
    try:
        server = BoundedThreadingServer(('0.0.0.0', PORT), AuthenticationHandler)
        print 'Server is listening on %s:%s' % (whats_my_sexual_ip(), PORT)
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
