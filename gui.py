'''
信息安全上机作业：实现DES替代算法（二重DES、三重两密DES、三重三密DES）
'''

import tkinter as tk
import tkinter.messagebox as tkm
import pyDes
import random

class MyDes:
    def __init__(self,key:str = ''):
        '''
        :param key: 密钥必须是8个字符长，即8bit * 8 = 64bit
        '''
        if not key:#如果没有传入密钥，自动设置
            self.key = self.random_key()
        else:
            self.key = key
        self.des = pyDes.des(self.key,padmode=pyDes.PAD_PKCS5)#初始化des类


    def encrypt(self,plain_text:bytes)-> bytes:
        '''
        des加密
        :param plain_text: 明文
        :return: 密文
        '''
        return self.des.encrypt(plain_text,padmode=pyDes.PAD_PKCS5)


    def decrypt(self,cipher_text:bytes) -> bytes:
        '''
        des解密
        :param cipher_text: 密文
        :return: 明文
        '''

        return self.des.decrypt(cipher_text,padmode=pyDes.PAD_PKCS5)

    def random_key(self):
        alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()'
        return ''.join(random.sample(alphabet,8))



    def bytesToHexString(self,bs):
        '''
        将字节串转换为十六进制字符串
        eg:
        b'\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef'
        '01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF'
        '''
        return ''.join(['%02X ' % b for b in bs])


    def hexStringTobytes(self,str):
        '''
        将十六进制字符串转换为字节串
        eg:
        '01 23 45 67 89 AB CD EF 01 23 45 67 89 AB CD EF'
        b'\x01#Eg\x89\xab\xcd\xef\x01#Eg\x89\xab\xcd\xef'
        '''
        str = str.replace(" ", "")
        return bytes.fromhex(str)

class MyDesGui:

    root = tk.Tk()
    des = MyDes()
    key_var = tk.StringVar()  # 密钥
    key2_var = tk.StringVar()
    key3_var = tk.StringVar()
    plain_text_var = tk.StringVar()  # 明文
    cipher_text_var = tk.StringVar()  # 密文

    def __init__(self):
        self.initComponent()
        self.random_key()  # 随机密钥
        self.root.mainloop()

    def initComponent(self):

        des_LF = tk.LabelFrame(self.root, text='DES')
        des_LF.grid(row=0, column=0)

        # 标签
        tk.Label(des_LF, text='明文').grid(row=0, column=0)
        tk.Label(des_LF, text='密钥1').grid(row=1, column=0)
        tk.Label(des_LF, text='密钥2').grid(row=2, column=0)
        tk.Label(des_LF, text='密钥3').grid(row=3, column=0)
        tk.Label(des_LF, text='密文').grid(row=4, column=0)
        # 输入框
        tk.Entry(des_LF,textvariable=self.plain_text_var).grid(row=0,column=1)
        tk.Entry(des_LF,textvariable=self.key_var).grid(row=1,column=1)
        tk.Entry(des_LF, textvariable=self.key2_var).grid(row=2, column=1)
        tk.Entry(des_LF, textvariable=self.key3_var).grid(row=3, column=1)
        tk.Entry(des_LF,textvariable=self.cipher_text_var).grid(row=4,column=1)
        # 按钮
        tk.Button(des_LF,text='DES加密',
                  command=lambda:self.encrypt(self.key_var.get())
                  ).grid(row=0,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF, text='二重DES加密',
                  command=lambda: self.double_des_encrypt()
                  ).grid(row=0, column=3, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重两密加密',
                  command=lambda: self.encrypt(self.key_var.get())
                  ).grid(row=0, column=4, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重三密加密',
                  command=lambda: self.encrypt(self.key_var.get())
                  ).grid(row=0, column=5, stick=tk.W + tk.E)

        tk.Button(des_LF,text='随机生成密钥1',command=lambda:self.random_key(self.key_var)).grid(row=1,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF, text='随机生成密钥2', command=lambda:self.random_key(self.key2_var)).grid(row=2, column=2, stick=tk.W + tk.E)
        tk.Button(des_LF, text='随机生成密钥3', command=lambda:self.random_key(self.key3_var)).grid(row=3, column=2, stick=tk.W + tk.E)
        tk.Button(des_LF,text='DES解密',
                  command=lambda:self.decrypt(self.key_var.get())
                  ).grid(row=4,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF, text='二重DES解密',
                  command=lambda: self.double_des_decrypt()
                  ).grid(row=4, column=3, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重两密解密',
                  command=lambda: self.decrypt(self.key_var.get())
                  ).grid(row=4, column=4, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重三密解密',
                  command=lambda: self.decrypt(self.key_var.get())
                  ).grid(row=4, column=5, stick=tk.W + tk.E)

    def random_key(self,key_var:tk.StringVar=None):
        if not key_var:
            key_var = self.key_var

        key_var.set(self.des.random_key())

    def show_plain_text(self,plain_text_b:bytes):
        '''
        显示明文
        :param plain_text_b: 明文的字节串
        :return:
        '''
        if not plain_text_b:
            return
        plain_text = plain_text_b.decode(errors='ignore')
        self.plain_text_var.set(plain_text)

    def show_cipher_text(self,cipher_text_b:bytes):
        '''
        显示密文
        :param cipher_text_b: 密文的字节串
        :return:
        '''
        if not cipher_text_b:
            return
        cipher_text = self.des.bytesToHexString(cipher_text_b)
        # 显示密文
        self.cipher_text_var.set(cipher_text)

    def encrypt(self,key:str,plain_text_b:bytes = None):
        '''
        DES加密
        :param key:
        :param plain_text_b: 明文字节串
        :return:
        '''
        if plain_text_b == None:
            plain_text_b = self.plain_text_var.get().encode()

        self.des = MyDes(key)  # 刷新密钥
        # 加密
        cipher_text_b = self.des.encrypt(plain_text_b)
        # 显示
        self.show_cipher_text(cipher_text_b)
        return cipher_text_b



    def decrypt(self,key:str,cipher_text_b:bytes = None):
        '''
        DES解密
        :param key:
        :param cipher_text_b: 8的整数倍密文字节串
        :return:
        '''
        if cipher_text_b == None:
            cipher_text_b = self.des.hexStringTobytes(self.cipher_text_var.get())

        self.des = MyDes(key)  # 刷新密钥
        # 解密
        plain_text_b = self.des.decrypt(cipher_text_b)
        # 显示
        self.show_plain_text(plain_text_b)
        return plain_text_b

    def double_des_encrypt(self):
        '''
        二重DES加密
        :return: 密文字节串
        '''
        # C = E_k2(E_k1(P))
        x_text_b = self.encrypt(self.key_var.get())  # 用key1进行加密

        if not x_text_b:
            return None

        cipher_text_b = self.encrypt(self.key2_var.get(),x_text_b)  # 用key2进行加密

        # 显示
        self.show_cipher_text(cipher_text_b)

        return cipher_text_b

    def double_des_decrypt(self):
        '''
        二重DES解密
        :return: 明文字节串
        '''
        # P = D_k1(D_k2(C))
        x_text_b = self.decrypt(self.key2_var.get())  # 用key2进行解密

        if not x_text_b:
            return None

        plain_text_b = self.decrypt(self.key_var.get(),x_text_b)  # 用key1进行解密

        # 显示
        self.show_plain_text(plain_text_b)

        return plain_text_b

    def triple_two_keys_encrypt(self):
        '''
        三重两密加密
        :return:
        '''
        # C = E_k1(D_k2(E_k1(P)))
        a_text_b = self.encrypt(self.key_var.get())
        b_text_b = self.decrypt(self.key2_var.get(),a_text_b)
        cipher_text_b = self.encrypt(self.key_var.get(),b_text_b)

        self.show_cipher_text(cipher_text_b)

        return cipher_text_b




    def triple_two_keys_decrypt(self):
        '''
        三重两密解密
        :return:
        '''
        # P = D_k1(E_k2(D_k1(C)))
        b_text_b = self.decrypt(self.key_var.get())
        a_text_b = self.encrypt(self.key2_var.get(),b_text_b)
        plain_text_b = self.decrypt(self.key_var.get(),a_text_b)

        self.show_plain_text(plain_text_b)

        return plain_text_b

    def triple_three_keys_encrypt(self):
        pass

    def triple_three_keys_decrypt(self):
        pass

if __name__ == '__main__':
    myGui = MyDesGui()

