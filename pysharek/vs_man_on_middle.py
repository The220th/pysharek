# -*- coding: utf-8 -*-

import hashlib

from .sup import *


def challenge_with_words(shared_key: str) -> None:
    text_bag = ('station', 'senior', 'husband', 'flood', 'storm', 'baker', 'orbit', 'sky', 'avenue', 'valley',
                'hurricane', 'motorcycle', 'lightning', 'air', 'man', 'canyon', 'designer', 'in-law', 'moon',
                'park', 'corporation', 'quasar', 'painter', 'music', 'book', 'researcher',
                'asteroid', 'wife', 'sun', 'constellation', 'space', 'UFO', 'business', 'snow', 'cosmos', 'van',
                'client', 'grandchild', 'parent', 'uncle', 'highway', 'car', 'jungle', 'ice', 'tree', 'actress',
                'cinema', 'cove', 'comet', 'black hole', 'partner', 'subordinate', 'son', 'community',
                'company', 'university', 'king', 'lake', 'helicopter', 'taxi', 'alley', 'institution', 'plane',
                'clinic', 'lane', 'paper', 'star', 'brother', 'doctor', 'store', 'association',
                'universe', 'continent', 'land', 'sand', 'truck', 'rainbow', 'ball', 'union', 'river', 'judge',
                'baby', 'island', 'museum', 'league', 'programmer', 'sea', 'toddler', 'astronaut', 'bus', 'theater',
                'market', 'town', 'cousin', 'water', 'waterfall', 'factory', 'cat', 'meteor', 'crew', 'classmate',
                'city', 'princess', 'employee', 'country', 'beach', 'meteorite', 'club', 'rocket', 'fire', 'reef',
                'stranger', 'engineer', 'forest', 'squad', 'boat', 'satellite', 'cloud', 'school', 'garden', 'tornado',
                'college', 'student', 'house', 'port', 'drought', 'plaza', 'ocean', 'queen', 'child',
                'cafe', 'earthquake', 'neighbor', 'cosmology', 'organization', 'godfather', 'coast',
                'square', 'gravity', 'spaceship', 'group', 'planet', 'bay', 'village', 'alien', 'hospital', 'wind',
                'neighborhood', 'stream', 'customer', 'aunt', 'spouse', 'godmother', 'pond', 'teacher', 'library',
                'artist', 'boss', 'pen', 'network', 'nebula', 'road', 'rock', 'writer', 'tsunami', 'dog', 'party',
                'meteoroid', 'nephew', 'stone', 'eclipse', 'politician', 'band', 'state', 'boulevard', 'grandparent',
                'chair', 'prince', 'president', 'daughter', 'zoo', 'adult', 'bicycle', 'pub', 'street', 'cave',
                'phone', 'photographer', 'rain', 'government', 'athlete', 'harbor', 'astrophysics',
                'chef', 'plain', 'hill', 'sister', 'earth', 'teenager', 'peninsula', 'airport', 'singer', 'sibling',
                'mountain', 'thunder', 'scientist', 'spacecraft', 'family', 'shore', 'society', 'computer', 'desert',
                'colleague', 'astronomy', 'galaxy', 'friend', 'bar', 'team', 'woman', 'niece', 'actor',
                'director', 'restaurant', 'train', 'supernova', 'office', 'table', 'banker', 'lawyer', 'volcano',
                'shop', 'ship', 'subway', 'foot', 'coke', 'machine', 'hand', 'heart', 'amogus', 'branch', 'milk',
                'circle', 'saw', 'kitten', 'word', 'story', 'work', 'idea', 'chance', 'fact', 'game', 'sound',
                'weather', 'week', 'morning', 'minute')
    h = hashlib.sha256(shared_key.encode("utf-8"))
    bs = h.digest()
    words = []
    for i in range(10):
        b_i = bs[i]
        index_i = int(b_i)
        index_i = index_i % 256
        word_i = text_bag[index_i]
        words.append(word_i)
    user_in = input(f"Make sure that these words match on each side: \n\n\t\t{' '.join(words)} \n\n"
                    f"If this is NOT, then the connection is NOT secure (man in the middle) "
                    f"or another error has occurred. \n"
                    f"If these words matched? (Y/n) ")

    plog(f"Words = {words}. User enter={user_in}", 4)
    if not (user_in == "" or user_in[0].lower() in ["y", "1", "yes"]):
        pout(f"Exiting...")
        Global.sock.close()
        exit()
