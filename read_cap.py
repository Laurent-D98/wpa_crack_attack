# -*- coding: utf-8 -*-

# Fonction   :    read_cap
# Date       :    02/12/2019
# Authors    :    Damien LAURENT, Mathilde MERLAND
# State      :    OK
#
# Read a .cap file and extract some information from the first 4-way handshake that the file contains
#
# Usage:
#  NONCE_AP, NONCE_S, MAC_AP, MAC_STATION, MIC_msg_4, msg_4_wo_MIC = read_cap(file)
#
# - Entrees
#   file       :  wpa_handshake_8-03.cap (ex: ""../Reseau/wpa_handshake_8-03.cap"")
#
# - Sorties
#   NONCE_AP, NONCE_S, MAC_AP, MAC_STATION, MIC_msg_4, msg_4_wo_MIC au format hexadécimal

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




from scapy.all import *
import Reseau.scapy_eap
import binascii


def read_cap(file):
    """lis les information dans le fichier de capture : file"""
    packets = scapy.all.rdpcap(file)
    handshake_packets = []
    for index, packet_i in enumerate(packets):
        if "WPA_key" in packet_i.summary(): #si le paquet est un handshake_packet
            handshake_packets.append(packet_i)


    NONCE_AP = handshake_packets[0]["WPA_key"].nonce
    NONCE_S = handshake_packets[1]["WPA_key"].nonce
    MAC_AP = handshake_packets[0]["Dot11"].addr2
    MAC_STATION = handshake_packets[0]["Dot11"].addr1
    MIC_msg_4 = handshake_packets[3]["WPA_key"].wpa_key_mic

    msg_4 = handshake_packets[3]

    msg_4_copy = msg_4.copy()
    msg_4_copy["WPA_key"].delfieldval("wpa_key_mic")  #enlève le mic du message 4
    msg_4_wo_MIC = msg_4_copy.copy()
    msg_4_wo_MIC_wo_entete = bytes(msg_4_wo_MIC)[32:] #Dans le protocole, le MIC est calculé sur cette portion du paquet

    MAC_station = ""
    for c in MAC_STATION:
        if c != ":":
            MAC_station += c
    MAC_ap = ""
    for c in MAC_AP:
        if c != ":":
            MAC_ap += c

    MAC_station = binascii.a2b_hex(MAC_station)
    MAC_ap = binascii.a2b_hex(MAC_ap)

    return NONCE_AP, NONCE_S, MAC_ap, MAC_station, MIC_msg_4, msg_4_wo_MIC_wo_entete

#TEST
if __name__ == "__main__" :
    #file = "wpa_handshake_WPA1-01.cap"
    file = "../Reseau/wpa_handshake_8-03.cap"
    NONCE_AP, NONCE_S, MAC_AP, MAC_STATION, MIC_msg_4, msg_4_wo_MIC = read_cap(file)
    print(NONCE_AP)
    print(NONCE_S)
    print(MAC_AP)
    print(MAC_STATION)
    print(MIC_msg_4)
    print(msg_4_wo_MIC)