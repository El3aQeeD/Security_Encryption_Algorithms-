import json
from DES_Algorithm import * 

e=encrypt_des("Khaled and hany IS the best")
d=decrypt_des(e)
print(f"d::{e}")
print(f"d::{d}")
# s=""
# print(f"e{e}")
# for index in range(len(e)):
#     for index2 in range(len(e[index])):
#         s+=e[index][index2]
#     s+=","
# print(s)
# l=[]
# l2=[]
# print("------------------------------------------")
# for index in range(len(e)):
#     if e[index]==",":
#         l2.append(l)
#         l=[]
#         continue
#     l.append(e[index])
# print(len(l2[1]))