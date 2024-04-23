__version__ = 2.3
#=============================== IMPORTS ZONE ===============================
from datetime import datetime


#=============================== INIT ZONE ===============================

num_log = 0
# suppression des logs
tmp = open('gaza.log', 'w')
tmp.write(f'({num_log}) : {datetime.now()} : INIT : server start\n')
tmp.close()


#=============================== MAIN ZONE ===============================
def log(msg_type : str | list[str], msg_content : str, content_size_limit : int = 150, file : str = 'gaza')-> None:
    """
    Enregistre un message dans un fichier journal spécifié.
    
    Cette fonction ajoute une nouvelle entrée dans le fichier journal spécifié, 
    avec un numéro d'entrée, la date et l'heure actuelles, le type de message et 
    le contenu du message. Si le contenu du message dépasse la limite de taille 
    spécifiée, seuls les premiers caractères jusqu'à la limite sont enregistrés.
    
    Args:
        msg_type (str | list[str]): Le ou les types du message à enregistrer.
        msg_content (str): Le contenu du message à enregistrer.
        content_size_limit (int, optional): La limite de taille du contenu du message. 
                                            Par défaut, elle est fixée à 150 caractères.
        file (str, optional): Le nom du fichier journal dans lequel enregistrer le message. 
                              Par défaut, il est fixé à 'gaza.log'.
    
    Retourne:
        None
    """
    global num_log
    num_log += 1
    try:
        if isinstance(msg_type, list): msg_type = ' | '.join(msg_type)
        with open(f'{file}.log', 'a', encoding="UTF8") as file:
            file.write(f'({num_log}) : {datetime.now()} : {msg_type} : {msg_content[:content_size_limit]}\n')
    except Exception as e:
        with open(f'{file}.log', 'a', encoding="UTF8") as file:
            file.write(f'({num_log}) : {datetime.now()} : LOG_ERROR : {e}\n')


