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

class MyDesGui:

    root = tk.Tk()
    des = MyDes()
    key_var = tk.StringVar()  # 密钥
    plain_text_var = tk.StringVar()  # 明文
    cipher_text_var = tk.StringVar()  # 密文

    def __init__(self):
        self.initComponent()
        self.random_key()  # 随机密钥
        self.root.mainloop()

    def initComponent(self):

        des_LF = tk.LabelFrame(self.root, text='普通DES')
        des_LF.grid(row=0, column=0)

        tk.Label(des_LF, text='明文').grid(row=0, column=0)
        tk.Label(des_LF, text='密钥').grid(row=1, column=0)
        tk.Label(des_LF, text='密文').grid(row=2, column=0)

        tk.Entry(des_LF,textvariable=self.plain_text_var).grid(row=0,column=1)
        tk.Entry(des_LF,textvariable=self.key_var,state=tk.DISABLED).grid(row=1,column=1)
        tk.Entry(des_LF,textvariable=self.cipher_text_var).grid(row=2,column=1)

        tk.Button(des_LF,text='加密',command=self.encrypt).grid(row=0,column=2,stick=tk.W+tk.E,)
        tk.Button(des_LF,text='随机生成密钥',command=self.random_key).grid(row=1,column=2,stick=tk.W+tk.E)
        tk.Button(des_LF,text='解密',command=self.decrypt).grid(row=2,column=2,stick=tk.W+tk.E)

    def random_key(self):
        self.key_var.set(self.des.random_key())
        self.des = MyDes(self.key_var.get())  # 刷新密钥

    def encrypt(self):

        if not self.plain_text_var.get():
            tkm.showwarning('注意','明文不能为空')
            return None

        plain_text_b = self.plain_text_var.get().encode('ascii',errors='ignore')
        cipher_text_b = self.des.encrypt(plain_text_b)
        cipher_text = cipher_text_b.decode('ascii',errors='ignore')  # 将结果转换为str

        tkm.showinfo('len', len(cipher_text))
        tkm.showinfo('len_b', len(cipher_text_b))

        self.cipher_text_var.set(cipher_text)

        return cipher_text_b



    def decrypt(self):
        if not self.cipher_text_var.get():
            tkm.showwarning('注意', '密文不能为空')
            return None

        cipher_text_b = self.cipher_text_var.get().encode('ascii',errors='ignore')
        tkm.showinfo('len', len(self.cipher_text_var.get()))
        tkm.showinfo('len', len(cipher_text_b))

        plain_text_b = self.des.decrypt(cipher_text_b)
        plain_text = plain_text_b.decode('ascii',errors='ignore')  # 将结果转换为str

        self.plain_text_var.set(plain_text)
        tkm.showinfo('text', plain_text)
        tkm.showinfo('len', len(plain_text))

        return plain_text_b


if __name__ == '__main__':
    myGui = MyDesGui()

