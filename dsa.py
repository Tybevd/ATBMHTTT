from random import randrange


from Crypto.Util.number import *
from random import *
from hashlib import sha1
# Hàm băm thông điệp bằng sha1
def hash_function(message):
    hashed=sha1(message.encode("UTF-8")).hexdigest()
    return hashed
# Hàm tìm nghịch đảo của a mũ -1 mod m
def mod_inverse(a,m):
    a=a%m
    for x in range(1,m):
        if((a*x)%m==1):
            return(x)
    return(1)
# Hàm sinh các tham số (p,q,g)
def parameter_generation():
    q=getPrime(5)
    p=getPrime(10)
    while((p-1)%q!=0):
        q=getPrime(5)
        p=getPrime(10)
    flag=True
    while(flag):
        h=int(input("Enter integer(h) between 1 and p-1: "))
        if(1<h<(p-1)):
            g=1
            while(g==1):
                g=pow(h,int((p-1)/q))%p
            flag=False
        else:
            print("Wrong entry")
    print("p=",p)
    print("q=",q)
    print("g=",g)
    return(p,q,g)

def per_user_key(p,q,g):
    x=randint(1,q-1)
    print("x=",x)
    y=pow(g,x)%p
    print("y=",y)
    return(x,y)

def signature(name,p,q,g,x):
    with open(name) as file:
        text=file.read()
        hash_component=hash_function(text)
        print("Hash of document sent is: ", hash_component)
    r=0
    s=0
    while(r==0 or s==0):
        k=randint(0,q)
        r=(pow(g,k)%p)%q
        i=mod_inverse(k,q)
        hashed=int(hash_component,16)
        hashed=67
        s=(i*(hashed+(x*r)))%q

    print("hashed=",hashed)
    print("i=",i)
    return(r,s,k)
def verification(name,p,q,g,r,s,y):
    with open(name) as file:
        text=file.read()
        hash_component=hash_function(text)
        print("Hash of document received is: ",hash_component)

    w=mod_inverse(s,q)
    hashed=int(hash_component,16)
    u1=(hashed*w)%q
    u2=(r*w)%q
    v=((pow(g,u1)*pow(y,u2))%p)%q
    print("u1=",u1)
    print("u2=",u2)
    print("v=",v)
    if(v==r): print("The signature is valid")
    else: print("The signature is invalid")

global_var=parameter_generation()
keys=per_user_key(global_var[0],global_var[1],global_var[2])
print()
file_name=input("Enter the name of document to sign: ")
components=signature(file_name,global_var[0],global_var[1],global_var[2],keys[0])
print("r is:", components[0])
print("k is:", components[2])
print("s is:", components[1])

print()
file_name=input("Enter the name of document to verify: ")
verification(file_name,global_var[0],global_var[1],global_var[2],components[0],components[1],keys[1])
