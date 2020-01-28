# Fonction   :    read_dico
# Date       :    02/12/2019
# Authors    :    Damien LAURENT, Mathilde MERLAND
# State      :    OK
#
# Read the dictionary in the file dictionary.tkt
#
# Usage:
#  dico  = read_dico(filename)
#
# - Entrees
#   filename         :  dictionary.tkt (ex: "dictionary.tkt")
#
# - Sorties
#   dico (list of string)

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


def read_dico(filename, path):
    dico=[]
    try:
        os_path = "../" +path + "/" + filename
        with open(os_path, "r") as f:
            for line in f:
                dico.append(line[0:8])
        return dico
    except:
        print("If Read_dico doesn't work, please check if the path to find the file is correct in Read_dico.py")

# TEST
if __name__ == "__main__":
    path = "Dictionary"
    filename = "dictionary.txt"
    dico = read_dico(filename, path)
    print(dico)
