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
        self.des = pyDes.des(self.key)#初始化des类


    def encrypt(self,plain_text:bytes)-> bytes:
        '''
        des加密
        :param plain_text: 明文
        :return: 密文
        '''
        return self.des.encrypt(plain_text,pad=' ',padmode=pyDes.PAD_NORMAL)


    def decrypt(self,cipher_text:bytes) -> bytes:
        '''
        des解密
        :param cipher_text: 密文
        :return: 明文
        '''

        return self.des.decrypt(cipher_text)

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
        self.random_key(self.key2_var)
        self.random_key(self.key3_var)
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
                  command=lambda:self.encrypt(self.key_var.get(),isShow=True)
                  ).grid(row=0,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF, text='二重DES加密',
                  command=lambda: self.double_des_encrypt()
                  ).grid(row=0, column=3, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重两密加密',
                  command=lambda: self.triple_two_keys_encrypt()
                  ).grid(row=0, column=4, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重三密加密',
                  command=lambda: self.triple_three_keys_encrypt()
                  ).grid(row=0, column=5, stick=tk.W + tk.E)

        tk.Button(des_LF,text='随机生成密钥1',command=lambda:self.random_key(self.key_var)).grid(row=1,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF, text='随机生成密钥2', command=lambda:self.random_key(self.key2_var)).grid(row=2, column=2, stick=tk.W + tk.E)
        tk.Button(des_LF, text='随机生成密钥3', command=lambda:self.random_key(self.key3_var)).grid(row=3, column=2, stick=tk.W + tk.E)
        tk.Button(des_LF,text='DES解密',
                  command=lambda:self.decrypt(self.key_var.get(),isShow=True)
                  ).grid(row=4,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF, text='二重DES解密',
                  command=lambda: self.double_des_decrypt()
                  ).grid(row=4, column=3, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重两密解密',
                  command=lambda: self.triple_two_keys_decrypt()
                  ).grid(row=4, column=4, stick=tk.W + tk.E)
        tk.Button(des_LF, text='三重三密解密',
                  command=lambda: self.triple_three_keys_decrypt()
                  ).grid(row=4, column=5, stick=tk.W + tk.E)

        prompt = '密钥长度为8个字符，即64bit;\n密文以十六进制字符串的形式展示'

        tk.Label(des_LF,text=prompt).grid(row=1,column=3,columnspan=3,rowspan=3)

    def random_key(self,key_var:tk.StringVar=None):
        if not key_var:
            key_var = self.key_var

        key_var.set(self.des.random_key())

    def check_key(self,key:str = None):
        '''
        检测填入密钥的合法性
        :return: 密钥是否正确
        '''
        if not key:
            keys = [self.key_var.get(),self.key2_var.get(),self.key3_var.get()]
        else:
            keys = [key]

        for key in keys:
            if len(key) != 8:
                tkm.showwarning('注意','密钥长度必须为8个字符，即64bit')
                return False
        return True


    def show_plain_text(self,plain_text_b:bytes):
        '''
        显示明文
        :param plain_text_b: 明文的字节串
        :return:
        '''
        if not plain_text_b:
            return
        plain_text = plain_text_b.decode(errors='ignore').strip()
        self.plain_text_var.set(plain_text)

    def show_cipher_text(self,cipher_text_b:bytes):
        '''
        显示密文
        :param cipher_text_b: 密文的字节串
        :return:
        '''
        if not cipher_text_b:
            return
        cipher_text = self.des.bytesToHexString(cipher_text_b).strip()
        # 显示密文
        self.cipher_text_var.set(cipher_text)

    def encrypt(self,key:str,plain_text_b:bytes = None,isShow:bool = False):
        '''
        DES加密
        :param key:
        :param plain_text_b: 明文字节串
        :return:
        '''
        if self.check_key(key) == False:
            return None
        if plain_text_b == None:
            plain_text_b = self.plain_text_var.get().encode()

        self.des = MyDes(key)  # 刷新密钥
        # 加密
        cipher_text_b = self.des.encrypt(plain_text_b)
        # 显示
        if isShow:
            self.show_cipher_text(cipher_text_b)
        return cipher_text_b



    def decrypt(self,key:str,cipher_text_b:bytes = None,isShow:bool = False):
        '''
        DES解密
        :param key:
        :param cipher_text_b: 8的整数倍密文字节串
        :return:
        '''
        if self.check_key(key) == False:
            return None
        if cipher_text_b == None:
            cipher_text_b = self.des.hexStringTobytes(self.cipher_text_var.get())

        self.des = MyDes(key)  # 刷新密钥
        # 解密
        plain_text_b = self.des.decrypt(cipher_text_b)
        # 显示
        if isShow:
            self.show_plain_text(plain_text_b)
        return plain_text_b

    def double_des_encrypt(self):
        '''
        二重DES加密
        :return: 密文字节串
        '''
        if self.check_key() == False:
            return None
        # C = E_k2(E_k1(P))
        x_text_b = self.encrypt(self.key_var.get())  # 用key1进行加密

        if not x_text_b:
            return None

        cipher_text_b = self.encrypt(self.key2_var.get(),x_text_b,isShow=True)  # 用key2进行加密

        return cipher_text_b

    def double_des_decrypt(self):
        '''
        二重DES解密
        :return: 明文字节串
        '''
        if self.check_key() == False:
            return None
        # P = D_k1(D_k2(C))
        x_text_b = self.decrypt(self.key2_var.get())  # 用key2进行解密

        if not x_text_b:
            return None

        plain_text_b = self.decrypt(self.key_var.get(),x_text_b,isShow=True)  # 用key1进行解密

        return plain_text_b

    def triple_two_keys_encrypt(self):
        '''
        三重两密加密
        :return:
        '''
        if self.check_key() == False:
            return None
        # C = E_k1(D_k2(E_k1(P)))
        a_text_b = self.encrypt(self.key_var.get())
        b_text_b = self.decrypt(self.key2_var.get(),a_text_b)
        cipher_text_b = self.encrypt(self.key_var.get(),b_text_b,isShow=True)
        return cipher_text_b




    def triple_two_keys_decrypt(self):
        '''
        三重两密解密
        :return:
        '''
        if self.check_key() == False:
            return None
        # P = D_k1(E_k2(D_k1(C)))
        b_text_b = self.decrypt(self.key_var.get())
        a_text_b = self.encrypt(self.key2_var.get(),b_text_b)
        plain_text_b = self.decrypt(self.key_var.get(),a_text_b,isShow=True)

        return plain_text_b

    def triple_three_keys_encrypt(self):
        '''
        三重三密加密
        :return:
        '''
        if self.check_key() == False:
            return None
        # C = E_k3(D_k2(E_k1(P)))
        a_text_b = self.encrypt(self.key_var.get())
        b_text_b = self.decrypt(self.key2_var.get(), a_text_b)
        cipher_text_b = self.encrypt(self.key3_var.get(), b_text_b,isShow=True)

        return cipher_text_b

    def triple_three_keys_decrypt(self):
        '''
        三重三密解密
        :return:
        '''
        if self.check_key() == False:
            return None
        # P = D_k1(E_k2(D_k3(C)))
        b_text_b = self.decrypt(self.key3_var.get())
        a_text_b = self.encrypt(self.key2_var.get(), b_text_b)
        plain_text_b = self.decrypt(self.key_var.get(), a_text_b,isShow=True)

        return plain_text_b


if __name__ == '__main__':
    myGui = MyDesGui()

