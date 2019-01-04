import sys
import socket
import json
import hashlib
import random
import time
from peewee import *
import stomp
import boto3

def print_func_name(func):
    def wrapper(*func_args, **func_argv):
        print('Start func: ', func.__name__)
        return func(*func_args, **func_argv)
    return wrapper

db = MySQLDatabase(
    'NP',
    user = 'Alan',
    passwd = '12345678',
    host = 'np2019.cv7z6vaorvye.us-west-2.rds.amazonaws.com',
    port = 3306
)

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(64, unique = True)
    token = CharField(64, null = True)
    # AMQ channel = token
    password = CharField(64)

class FriendPair(BaseModel):
    # friend_1 has smaller ID than friend_2
    friend_1 = ForeignKeyField(User, related_name = 'friends_1')
    friend_2 = ForeignKeyField(User, related_name = 'friends_2')

class FriendInvite(BaseModel):
    receiver = ForeignKeyField(User, related_name = 'recv_invites')
    sender = ForeignKeyField(User, related_name = 'send_invites')

class Post(BaseModel):
    user = ForeignKeyField(User, related_name = 'posts')
    text = TextField()

class Group(BaseModel):
    groupname = CharField(64, unique = True)
    channel = CharField(64)

class GroupMember(BaseModel):
    group = ForeignKeyField(Group, related_name = 'members')
    user = ForeignKeyField(User, related_name = 'groups')

class APPServer(BaseModel):
    instance_id = CharField(64, unique = True)
    server_ip = CharField(64, unique = True)

class ServerMember(BaseModel):
    server = ForeignKeyField(APPServer, related_name = 'members')
    user = ForeignKeyField(User, related_name = 'server')

class Server:
    def __init__(self, _host, _port):
        self.server_max_loading = 10
        self.host = _host
        self.port = _port
        self.cmd_str = ''
        self.cmd_frag = []
        self.cmd_switch = {
            'register':     self.register,
            'login':        self.login,
            'delete':       self.delete,
            'logout':       self.logout,
            'invite':       self.wrongServer,
            'list-invite':  self.wrongServer,
            'accept-invite':self.wrongServer,
            'list-friend':  self.wrongServer,
            'post':         self.wrongServer,
            'receive-post': self.wrongServer,
            'send':         self.wrongServer,
            'create-group': self.wrongServer,
            'list-group':   self.wrongServer,
            'list-joined':  self.wrongServer,
            'join-group':   self.wrongServer,
            'send-group':   self.wrongServer
        }
        db.connect()
        db.create_tables([User, FriendPair ,FriendInvite, Post,
                        Group, GroupMember,
                        APPServer, ServerMember])

        self.ec2 = boto3.resource('ec2')

    def run(self):
        while True:
            self.passiveTCP()

    def passiveTCP(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            print('--------------------')
            print('Sever is ready for listening...')
            s.listen(1)
            client, addr = s.accept()
            with client:
                print(time.asctime(time.localtime()))
                print('Connect: ', addr)
                self.cmd_str = client.recv(1024).decode()
                print('Received: ', self.cmd_str)
                client.sendall(self.cmdProcess().encode('UTF-8'))
                s.close()
    
    def receiveAPPServerWakeup(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, 8787))
            print('Waiting for APPServer initialization...')
            s.listen(1)
            client, addr = s.accept()
            with client:
                print(time.asctime(time.localtime()))
                print('Recv instance:', addr)
                s.close()

    #@staticmethod
    def createResp(self, status, message = '', 
    token = '', post = '', friend = '', invite = '', 
    group_info = '', group = '',
    server_ip = ''):
        resp = { 'status': status }
        if token:
            resp['token'] = token
        if message:
            resp['message'] = message
        if self.cmd_frag[0] == 'receive-post' and not status:
            resp['post'] = post
        if self.cmd_frag[0] == 'list-friend' and not status:
            resp['friend'] = friend
        if self.cmd_frag[0] == 'list-invite' and not status:
            # Cause invite could be a null list
            resp['invite'] = invite
        if (self.cmd_frag[0] == 'list-group' or self.cmd_frag[0] == 'list-joined')\
        and not status:
            resp['group'] = group
        if group_info:
            resp['group_info'] = group_info
        if server_ip:
            resp['server_ip'] = server_ip

        return json.dumps(resp)

    @staticmethod
    def createRandomToken():
        return hashlib.sha256(str(random.random()).encode('UTF-8')).hexdigest()

    def checkToken(self):
        try:
            user = User.select().where(User.token == self.cmd_frag[1])
        except:
            return None
        if not user:
            print('XXX: Not login yet')
            return None
        if len(user) > 1:
            print('!!!: Multiple users')
        return user[0]

    def getAvailableServer(self):
        server = (APPServer.select()
                        .join(ServerMember)
                        .join(User)
                        .group_by(APPServer)
                        .having(fn.Count(User.id) < self.server_max_loading)
                        .order_by(fn.Count(User.id)))

        for s in server:
            print('Server {0} remains {1} members'.format(s.instance_id, len(s.members)))

        if server:
            return server[0]
        
        ni = self.ec2.create_network_interface(
            SubnetId = 'subnet-01877c78',
            Groups = ['sg-037535fe55503e9cb']
        )
        print('Get private IP:', ni.private_ip_address)
        print('Create APP-Server Instance...')
        instance = self.ec2.create_instances(
        ImageId = 'ami-06c3d6d7e2e6dc62e',
        MinCount = 1,
        MaxCount = 1,
        KeyName = 'NP',
        InstanceType = 't2.micro',
        NetworkInterfaces =[{ 'NetworkInterfaceId': ni.id, 'DeviceIndex': 0}],
        UserData = '''#!/bin/bash
/usr/bin/python3 /home/ubuntu/app_server.py {0} 1234 
'''.format(ni.private_ip_address)
        )[0]
        instance.wait_until_running()
        instance.reload()
        print(instance.id, 'is created!')
        server = APPServer.create(
            instance_id = instance.id,
            server_ip = instance.public_ip_address
        )
        self.receiveAPPServerWakeup()
        return server

    def checkServerLoading(self, server):
        print('{0} remains {1} members!'.format(server.instance_id, len(server.members)))
        if not server.members:
            i = self.ec2.instances.filter(InstanceIds = [server.instance_id])
            i.terminate()
            server.delete_instance(recursive = True)

    def cmdProcess(self):
        self.cmd_frag = self.cmd_str.split(' ')
        return self.cmd_switch.get(self.cmd_frag[0], self.exception)()

    @print_func_name
    def exception(self):
        print('XXX: Unknown Command')
        return self.createResp(1, message = 'Unknown command '+self.cmd_frag[0])

    @print_func_name
    def wrongServer(self):
        print('XXX: Not login yet')
        return self.createResp(1, message = 'Not login yet')

    @print_func_name
    def register(self):
        # Usage failed
        if len(self.cmd_frag) != 3:
            print('XXX: Usage error')
            return self.createResp(1, message = 'Usage: register <id> <password>')

        username, password = self.cmd_frag[1:3]
        print('Create user: {0}, {1}'.format(username, password))

        # Check if username is used
        if(User.select().where(User.username == username)):
            print('XXX: Username used')
            return self.createResp(1, message = username + ' is already used')
        
        # Create account
        new_user = User.create(
            username = username,
            password = hashlib.sha256(password.encode('UTF-8')).hexdigest()
            )
        print('OOO')
        return self.createResp(0, message = 'Success!')
    
    @print_func_name
    def login(self):
        # Usage failed
        if len(self.cmd_frag) != 3:
            print('XXX: Usage error')
            return self.createResp(1, message = 'Usage: login <id> <password>')
        
        username, password = self.cmd_frag[1:3]
        print('Login user: {0}, {1}'.format(username, password))
        
        # Check user
        user = User.select().where(User.username == username)
        if not user:
            print('XXX: No such user')
            return self.createResp(1, message = 'No such user or password error')
        if len(user) != 1:
            print('!!!: Multiple users')
        user = user[0]

        # Check password
        if hashlib.sha256(password.encode('UTF-8')).hexdigest() != user.password:
            print('XXX: Password doesnt match')
            return self.createResp(1, message ='No such user or password error')
        
        # Create and send Token
        if not user.token:
            user.token = self.createRandomToken()
            user.save()
        
        # Check APP Server
        server_pair = ServerMember.select().where(ServerMember.user == user)
        if server_pair:
            server = server_pair[0].server
        else:
            server = self.getAvailableServer()
            ServerMember.create(
                server = server,
                user = user
            )

        # Send AMQ group channel
        group_info = list(map(
            lambda x: {'groupname': x.group.groupname, 'channel': x.group.channel},
            user.groups
        ))

        print('OOO: token = ' + user.token)
        return self.createResp(
            0,
            token = user.token,
            group_info = group_info,
            server_ip = server.server_ip,
            message = 'Success!')

    @print_func_name
    def delete(self):
        # Check user
        user = self.checkToken()
        if not user:
            return self.createResp(1, message = 'Not login yet')

        # Usage failed
        if len(self.cmd_frag) != 2:
            print('XXX: Usage error')
            return self.createResp(1, message = 'Usage: delete <user>')
        
        # Delete user-related data 
        server = user.server[0].server
        user.delete_instance(recursive = True) #Fucking EZ!!

        # Check Server customers
        self.checkServerLoading(server)

        print('OOO')
        return self.createResp(0, message = 'Success!')
    
    @print_func_name
    def logout(self):
        # Check user
        user = self.checkToken()
        if not user:
            return self.createResp(1, message = 'Not login yet')
        
        # Usage failed
        if len(self.cmd_frag) != 2:
            print('XXX: Usage error')
            return self.createResp(1, message = 'Usage: logout <user>')
        
        # Clear token
        user.token = None
        user.save()

        # Detach server
        server = user.server[0].server
        user.server[0].delete_instance()
        self.checkServerLoading(server)

        print('OOO')
        return self.createResp(0, message = 'Bye!')

   
# main
if len(sys.argv) < 2 or len(sys.argv) > 3:
    print('Usage: python3 <program.py> <Host> <Port>')
    exit(0)
elif len(sys.argv) == 2:
    host = socket.INADDR_LOOPBACK
    port = sys.argv[1]
else:
    host, port = sys.argv[1:3]
    
server = Server(str(host), int(port))
server.run()