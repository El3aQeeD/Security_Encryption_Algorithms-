#!/usr/bin/env python
# coding: utf-8

# In[19]:


import secrets #for random select and its more secure than random

# Global Public Elements
q = 144680345296684229304575179529938245101116505796297724604093354959605529698553710091437622563823349977233953598919282328617313556530076978689781274705883651331885037231666129678790666583467909689725051848798939477054509622827204488057693951443317602316042032987991969996748116892536606440843751763423931593  # A large prime number
a = 3  # a < q and a is a primitive root of q

def Key_Generation(q, a):
    X = secrets.randbelow(q - 1) + 1  # select private Xa "private key"
    Y = pow(a, X, q)  # Calculate Ya "Public key"
    return Y, X  # Public key, Private key


def shared_session_key(private_key, public_key2):
    X = private_key
    Y2 = public_key2
    K = pow(Y2, X, q)
    
    # Ensure that the shared keys are the same
    # if Ka == Kb: 
    #     print("Shared keys are equal")
    
    return K

